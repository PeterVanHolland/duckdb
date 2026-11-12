//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/swar.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/bit_utils.hpp"
#include "duckdb/common/bswap.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/typedefs.hpp"
#include "duckdb/common/vector.hpp"

namespace duckdb {

//! SWAR primitives over the eight bytes of a uint64_t, the masks flag a byte by setting its high bit
struct SwarWord {
	static constexpr idx_t SIZE = sizeof(uint64_t);
	static constexpr uint64_t LSB = 0x0101010101010101ULL;
	static constexpr uint64_t MSB = 0x8080808080808080ULL;
	static constexpr uint64_t LOW7 = 0x7F7F7F7F7F7F7F7FULL;

	//! A word with every byte set to `byte`
	static inline uint64_t Repeat(uint8_t byte) {
		return LSB * byte;
	}

	//! Flags every byte of `word` that is zero, exact for all byte values
	static inline uint64_t ZeroBytes(uint64_t word) {
		return ~(((word & LOW7) + LOW7) | word) & MSB;
	}

	//! Flags every zero byte of `word` and possibly bytes above one, cheaper than ZeroBytes for callers that verify
	static inline uint64_t MaybeZeroBytes(uint64_t word) {
		return (word - LSB) & ~word & MSB;
	}

	//! Whether no byte of `word` has its high bit set
	static inline bool IsAscii(uint64_t word) {
		return (word & MSB) == 0;
	}

	//! Sums up the individual bytes of `word`, only valid if the sum does not exceed 255
	static inline idx_t SumBytes(uint64_t word) {
		return static_cast<idx_t>((word * LSB) >> 56);
	}

	//! The number of set bits of a word
	static inline idx_t CountSetBits(uint64_t word) {
#if defined(__GNUC__) || defined(__clang__)
		return static_cast<idx_t>(__builtin_popcountll(word));
#else
		word = word - ((word >> 1) & 0x5555555555555555ULL);
		word = (word & 0x3333333333333333ULL) + ((word >> 2) & 0x3333333333333333ULL);
		word = (word + (word >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
		return static_cast<idx_t>((word * LSB) >> 56);
#endif
	}
	//! The number of flagged bytes in a mask
	static inline idx_t CountFlagged(uint64_t mask) {
		// every flagged byte has its high bit set, shifted down each byte is a zero or a one
		return SumBytes(mask >> 7);
	}

	//! The index (in memory order) of the first flagged byte in a mask
	static inline idx_t FirstFlagged(uint64_t mask) {
#if DUCKDB_IS_BIG_ENDIAN
		return CountZeros<uint64_t>::Leading(mask) / 8;
#else
		return CountZeros<uint64_t>::Trailing(mask) / 8;
#endif
	}

	//! Packs the flags of a mask into the low eight bits, byte i (in memory order) to bit i
	static inline uint64_t PackFlags(uint64_t mask) {
#if DUCKDB_IS_BIG_ENDIAN
		mask = BSwap(mask);
#endif
		return ((mask >> 7) * PACK_MULTIPLIER) >> 56;
	}

private:
	//! Moves the flag of byte i to bit 56 + i
	static constexpr uint64_t PACK_MULTIPLIER = 0x0102040810204080ULL;
};

//! Bit masks over blocks of 64 bytes, one bit per byte (bit i is byte i)
struct SwarBlock {
	static constexpr idx_t SIZE = 64;
	static constexpr idx_t WORDS = SIZE / SwarWord::SIZE;

	//! A byte pattern repeated over a word, a byte matches when it equals `value` on the bits set in `mask`
	struct BytePattern {
		//! Matches one byte
		static BytePattern Byte(uint8_t byte) {
			return BytePattern(byte, 0xff);
		}
		//! Matches both bytes, and every byte that agrees with them on the bits where they agree
		static BytePattern Either(uint8_t a, uint8_t b) {
			const auto mask = static_cast<uint8_t>(~(a ^ b));
			return BytePattern(a, mask);
		}
		uint64_t value;
		uint64_t mask;

	private:
		BytePattern(uint8_t value_p, uint8_t mask_p)
		    : value(SwarWord::Repeat(value_p & mask_p)), mask(SwarWord::Repeat(mask_p)) {
		}
	};

	//! The fewest and the most patterns MaybeAnyMask takes at once
	static constexpr idx_t MIN_PATTERNS = 2;
	static constexpr idx_t MAX_PATTERNS = 5;

	//! The 8x8 bit transpose: bit (j * 8 + i) of the result is bit (i * 8 + j) of `x`
	static inline uint64_t TransposeBits(uint64_t x) {
		uint64_t t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL;
		x = x ^ t ^ (t << 7);
		t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL;
		x = x ^ t ^ (t << 14);
		t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL;
		return x ^ t ^ (t << 28);
	}

	//! The bit mask of the 0x80 flags of a block of flag bytes, in byte order
	static inline uint64_t PackFlagBytes(const uint8_t *flags) {
		// word i contributes bit i of every byte, the transpose puts the bytes of word i at bits i * 8 to i * 8 + 7
		uint64_t transposed = 0;
		for (idx_t i = 0; i < WORDS; i++) {
			auto word = Load<uint64_t>(const_data_ptr_cast(flags + i * SwarWord::SIZE));
#if DUCKDB_IS_BIG_ENDIAN
			word = BSwap(word);
#endif
			transposed |= word >> (SwarWord::SIZE - 1 - i);
		}
		return TransposeBits(transposed);
	}

	//! Whether a byte of the block has its high bit set or equals `a` or `b`; a byte loop, which the compiler
	//! vectorizes
	static inline bool HasHighBitOrBytes(const_data_ptr_t block, const uint8_t a, const uint8_t b) {
		uint8_t any = 0;
		for (idx_t i = 0; i < SIZE; i++) {
			any |= static_cast<uint8_t>((block[i] & 0x80) | (block[i] == a ? 0xFF : 0) | (block[i] == b ? 0xFF : 0));
		}
		return any != 0;
	}

	//! The exact bit masks of the bytes of the block equal to `delimiter` and to `row_end`, and with OTHER_MASK to
	//! `other`; byte loops, which the compiler vectorizes
	template <bool OTHER_MASK>
	static inline void RowCountMasks(const_data_ptr_t block, const uint8_t delimiter, const uint8_t row_end,
	                                 const uint8_t other, uint64_t &delimiters, uint64_t &row_ends, uint64_t &others) {
		uint8_t delimiter_flags[SIZE];
		uint8_t row_end_flags[SIZE];
		for (idx_t i = 0; i < SIZE; i++) {
			delimiter_flags[i] = block[i] == delimiter ? 0x80 : 0;
		}
		for (idx_t i = 0; i < SIZE; i++) {
			row_end_flags[i] = block[i] == row_end ? 0x80 : 0;
		}
		if (OTHER_MASK) {
			uint8_t other_flags[SIZE];
			for (idx_t i = 0; i < SIZE; i++) {
				other_flags[i] = block[i] == other ? 0x80 : 0;
			}
			others = PackFlagBytes(other_flags);
		} else {
			others = 0;
		}
		delimiters = PackFlagBytes(delimiter_flags);
		row_ends = PackFlagBytes(row_end_flags);
	}

	//! Mask of the bytes matching any pattern plus possibly bytes right above a match, no match is ever missed
	static inline uint64_t MaybeAnyMask(const_data_ptr_t block, const vector<BytePattern> &patterns) {
		//! We have between 2 (delimiter/newline) and 5 (delimiter,newline,comment,quote,escape) patterns
		switch (patterns.size()) {
		case 2:
			return MaybeAnyMaskUnrolled<2>(block, patterns);
		case 3:
			return MaybeAnyMaskUnrolled<3>(block, patterns);
		case 4:
			return MaybeAnyMaskUnrolled<4>(block, patterns);
		case 5:
			return MaybeAnyMaskUnrolled<5>(block, patterns);
		default:
			throw InternalException("SwarBlock::MaybeAnyMask takes %d to %d patterns, got %d", MIN_PATTERNS,
			                        MAX_PATTERNS, patterns.size());
		}
	}

private:
	//! MaybeAnyMask with the pattern loop unrolled for a count known at compile time
	template <idx_t PATTERN_COUNT>
	static inline uint64_t MaybeAnyMaskUnrolled(const_data_ptr_t block, const vector<BytePattern> &patterns) {
		uint64_t mask = 0;
		for (idx_t i = 0; i < WORDS; i++) {
			const auto word = Load<uint64_t>(block + i * SwarWord::SIZE);
			uint64_t flags = 0;
			for (idx_t p = 0; p < PATTERN_COUNT; p++) {
				flags |= SwarWord::MaybeZeroBytes((word & patterns.get(p).mask) ^ patterns.get(p).value);
			}
			mask |= SwarWord::PackFlags(flags) << (i * SwarWord::SIZE);
		}
		return mask;
	}
};

} // namespace duckdb
