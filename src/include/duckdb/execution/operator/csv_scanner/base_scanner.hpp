//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/operator/csv_scanner/base_scanner.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/execution/operator/csv_scanner/csv_buffer_manager.hpp"
#include "duckdb/execution/operator/csv_scanner/scanner_boundary.hpp"
#include "duckdb/execution/operator/csv_scanner/csv_state_machine.hpp"
#include "duckdb/execution/operator/csv_scanner/csv_error.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/execution/operator/csv_scanner/csv_byte_skipper.hpp"

// the block scan loop's speed depends on where its code starts within a 64 byte line, so the function is aligned; the
// hooks it calls per structural byte are inlined into it
#if defined(__GNUC__)
#define DUCKDB_BLOCK_SCAN_ALIGNED __attribute__((aligned(64)))
#define DUCKDB_BLOCK_SCAN_INLINE  inline __attribute__((always_inline))
#else
#define DUCKDB_BLOCK_SCAN_ALIGNED
#define DUCKDB_BLOCK_SCAN_INLINE inline
#endif

namespace duckdb {

class CSVFileScan;

//! Class that keeps track of line starts, used for line size verification
class LinePosition {
public:
	LinePosition() {
	}
	LinePosition(idx_t buffer_idx_p, idx_t buffer_pos_p, idx_t buffer_size_p)
	    : buffer_pos(buffer_pos_p), buffer_size(buffer_size_p), buffer_idx(buffer_idx_p) {
	}

	idx_t operator-(const LinePosition &other) const {
		if (other.buffer_idx == buffer_idx) {
			return buffer_pos - other.buffer_pos;
		}
		return other.buffer_size - other.buffer_pos + buffer_pos;
	}

	bool operator==(const LinePosition &other) const {
		return buffer_pos == other.buffer_pos && buffer_idx == other.buffer_idx && buffer_size == other.buffer_size;
	}

	idx_t GetGlobalPosition(idx_t requested_buffer_size, bool first_char_nl = false) const {
		return requested_buffer_size * buffer_idx + buffer_pos + first_char_nl;
	}
	idx_t buffer_pos = 0;
	idx_t buffer_size = 0;
	idx_t buffer_idx = 0;
};

class ScannerResult {
public:
	ScannerResult(CSVStates &states, CSVStateMachine &state_machine, idx_t result_size);

	static inline void SetQuoted(ScannerResult &result, idx_t quoted_position) {
		if (!result.quoted) {
			result.quoted_position = quoted_position;
		}
		result.quoted = true;
		result.unquoted = true;
	}

	static inline void SetUnquoted(ScannerResult &result) {
		if (result.states.states[0] == CSVState::UNQUOTED && result.states.states[1] == CSVState::UNQUOTED &&
		    result.state_machine.dialect_options.state_machine_options.escape != '\0') {
			// This means we touched an unescaped quote, we must go through the remove escape code to remove it.
			result.escaped = true;
		}
		result.quoted = true;
	}

	static inline void SetEscaped(ScannerResult &result) {
		result.escaped = true;
	}
	static inline void SetComment(ScannerResult &result, idx_t buffer_pos) {
		result.comment = true;
	}
	static inline bool UnsetComment(ScannerResult &result, idx_t buffer_pos) {
		result.comment = false;
		return false;
	}
	static inline bool IsCommentSet(const ScannerResult &result) {
		return result.comment == true;
	}

	inline bool IsStateCurrent(CSVState state) const {
		return states.states[1] == state;
	}

	//! Results that materialize values override these, so the block scan skips the values nobody asked for
	template <class T>
	static inline bool CanSkipValue(const T &result) {
		return false;
	}
	template <class T>
	static inline void SkipValue(T &result, const idx_t buffer_pos) {
	}
	template <class T>
	static inline bool AddRowWithoutValue(T &result, const idx_t buffer_pos) {
		return false;
	}
	template <class T>
	static inline bool SkipsRuns(const T &result) {
		return false;
	}
	//! Results that can count the rows of plain blocks from the masks alone set this
	static constexpr bool CAN_COUNT_ROWS = false;
	template <class T>
	static inline bool CountsRowsOnly(const T &result) {
		return false;
	}
	template <class T>
	static inline bool AddCountedRows(T &result, const idx_t rows, const idx_t row_end, const idx_t after_row_end) {
		return false;
	}
	template <class T>
	static inline idx_t SkippableRun(const T &result, const idx_t buffer_pos) {
		return 0;
	}
	template <class T>
	static inline void SkipValues(T &result, const idx_t count, const idx_t first_buffer_pos, const idx_t buffer_pos) {
	}

	//! Variable to keep information regarding quoted and escaped values
	bool quoted = false;
	//! If the current quoted value is unquoted
	bool unquoted = false;
	//! If the current value has been escaped
	bool escaped = false;
	//! Variable to keep track if we are in a comment row. Hence, won't add it
	bool comment = false;
	idx_t quoted_position = 0;

	LinePosition last_position;

	//! Size of the result
	const idx_t result_size;

	CSVStateMachine &state_machine;
	bool cur_line_starts_as_comment = false;

	void Print() const {
		state_machine.Print();
	}

protected:
	CSVStates &states;
};

//! This is the base of our CSV scanners.
//! Scanners differ on what they are used for, and consequently have different performance benefits.
class BaseScanner {
public:
	explicit BaseScanner(shared_ptr<CSVBufferManager> buffer_manager, shared_ptr<CSVStateMachine> state_machine,
	                     shared_ptr<CSVErrorHandler> error_handler, bool sniffing = false,
	                     shared_ptr<CSVFileScan> csv_file_scan = nullptr, const CSVIterator &iterator = {});

	virtual ~BaseScanner() = default;

	void Print() const;

	//! Returns true if the scanner is finished
	bool FinishedFile() const;

	//! Parses data into an output_chunk
	virtual ScannerResult &ParseChunk();

	//! Returns the result from the last Parse call. Shouts at you if you call it wrong
	virtual ScannerResult &GetResult();

	CSVIterator &GetIterator();

	void SetIterator(const CSVIterator &it);

	idx_t GetBoundaryIndex() const {
		return iterator.GetBoundaryIdx();
	}

	idx_t GetLinesRead() const {
		return lines_read;
	}

	CSVPosition GetIteratorPosition() const {
		return iterator.pos;
	}

	CSVStateMachine &GetStateMachine() const;

	//! Removes thousands separator
	static string RemoveSeparator(const char *value_ptr, const idx_t size, char thousands_separator);

	shared_ptr<CSVFileScan> csv_file_scan;

	//! If this scanner is being used for sniffing
	bool sniffing = false;
	//! The guy that handles errors
	shared_ptr<CSVErrorHandler> error_handler;

	//! Shared pointer to the state machine, this is used across multiple scanners
	shared_ptr<CSVStateMachine> state_machine;

	//! States
	CSVStates states;

	//! If the scanner ever entered a quoted state
	bool ever_quoted = false;

	//! If the scanner ever entered an escaped state.
	bool ever_escaped = false;

	//! If the scanner ever used advantage of the non-strict mode.
	bool used_unstrictness = false;

	//! Shared pointer to the buffer_manager, this is shared across multiple scanners
	shared_ptr<CSVBufferManager> buffer_manager;

	//! Skips Notes and/or parts of the data, starting from the top.
	//! notes are dirty lines on top of the file, before the actual data
	static CSVIterator SkipCSVRows(shared_ptr<CSVBufferManager> buffer_manager,
	                               const shared_ptr<CSVStateMachine> &state_machine, idx_t rows_to_skip);

protected:
	//! Boundaries of this scanner
	CSVIterator iterator;

	//! Unique pointer to the buffer_handle, this is unique per scanner, since it also contains the necessary counters
	//! To offload buffers to disk if necessary
	shared_ptr<CSVBufferHandle> cur_buffer_handle;

	//! Hold the current buffer ptr
	const char *buffer_handle_ptr = nullptr;

	//! If this scanner has been initialized
	bool initialized = false;
	//! How many lines were read by this scanner
	idx_t lines_read = 0;
	idx_t bytes_read = 0;
	//! Internal Functions used to perform the parsing
	//! Initializes the scanner
	virtual void Initialize();

	//! Skips the content bytes of the current buffer, mutable because the line finder is const
	mutable CSVByteSkipper skipper;

	//! Whether ProcessBlocks may drive this state machine, and the bytes it stops at
	const bool block_scan;
	const uint8_t block_delimiter;
	const string block_delimiter_bytes;
	const bool block_multi_byte_delimiter;
	const uint8_t block_quote;
	const bool block_crlf;
	const bool block_cr;
	const bool block_escape_is_quote;
	const uint8_t block_comment;

	//! Whether the state machine can hand the current byte to ProcessBlocks
	template <class T>
	bool BlockScanPossible(const T &result) const {
		if (result.quoted || result.escaped || result.comment) {
			return false;
		}
		switch (states.states[1]) {
		case CSVState::STANDARD:
		case CSVState::DELIMITER:
		case CSVState::RECORD_SEPARATOR:
		case CSVState::EMPTY_SPACE:
		case CSVState::NOT_SET:
			return true;
		default:
			return false;
		}
	}

	static bool IsSeparatorState(const CSVState state) {
		return state == CSVState::DELIMITER || state == CSVState::RECORD_SEPARATOR ||
		       state == CSVState::CARRIAGE_RETURN || state == CSVState::NOT_SET;
	}

	//! The state after the data bytes [from, to) given the state `before` them, as the eligible tables have it
	CSVState StateAfterData(const CSVState before, const idx_t from, const idx_t to) const {
		if (from == to) {
			return before;
		}
		if (to - from == 1 && buffer_handle_ptr[from] == ' ' && IsSeparatorState(before)) {
			return CSVState::EMPTY_SPACE;
		}
		return CSVState::STANDARD;
	}

	//! Moves `states` from the pair before byte `last` to the pair before byte `at`, over data bytes
	void SetStatesBefore(const idx_t at, const idx_t last) {
		const auto before = states.states[1];
		const auto previous = at == last ? states.states[0] : StateAfterData(before, last, at - 1);
		D_ASSERT(ReplayStates(last, at).states[1] == StateAfterData(before, last, at));
		D_ASSERT(ReplayStates(last, at).states[0] == previous);
		states.states[1] = StateAfterData(before, last, at);
		states.states[0] = previous;
	}

	//! The pair the state machine reaches from `states` over the bytes [from, to), for the block scan assertions
	CSVStates ReplayStates(const idx_t from, const idx_t to) const {
		CSVStates replay = states;
		for (idx_t i = from; i < to; i++) {
			state_machine->Transition(replay, buffer_handle_ptr[i]);
		}
		return replay;
	}

	//! Moves `states` from the pair before byte `last` to the pair before byte `at`, over quoted data bytes
	void SetQuotedStatesBefore(const idx_t at, const idx_t last) {
		const auto previous = at == last ? states.states[0] : at == last + 1 ? states.states[1] : CSVState::QUOTED;
		D_ASSERT(ReplayStates(last, at).states[0] == previous);
		D_ASSERT(ReplayStates(last, at).states[1] == (at == last ? states.states[1] : CSVState::QUOTED));
		states.states[1] = at == last ? states.states[1] : CSVState::QUOTED;
		states.states[0] = previous;
	}

	//! Leaves the block scan inside a comment at `at`, `before` is the state before the comment byte at `last - 1`
	bool HandOverComment(const idx_t at, const idx_t last, const CSVState before) {
		const auto previous = at == last ? before : CSVState::COMMENT;
		D_ASSERT(ReplayStates(last, at).states[0] == previous);
		D_ASSERT(ReplayStates(last, at).states[1] == CSVState::COMMENT);
		states.states[0] = previous;
		states.states[1] = CSVState::COMMENT;
		iterator.pos.buffer_pos = at;
		return false;
	}

	//! Leaves the block scan inside a quoted value at `at`
	bool HandOverQuoted(const idx_t at, const idx_t last) {
		SetQuotedStatesBefore(at, last);
		iterator.pos.buffer_pos = at;
		return false;
	}

	//! The bytes that end a row at `at`, 2 for a CRLF pair that fits before `limit`, 1 for a line feed, else 0
	idx_t RowEndBytes(const uint8_t byte, const idx_t at, const idx_t limit) const {
		if (block_crlf) {
			return byte == '\r' && at + 1 < limit && buffer_handle_ptr[at + 1] == '\n' ? 2 : 0;
		}
		if (block_cr) {
			return byte == '\r' ? 1 : 0;
		}
		return byte == '\n' ? 1 : 0;
	}

	//! The bytes of the whole multi byte delimiter when it starts at `at` and ends before `limit`, 0 when only part of
	//! it is there. No loop here, a loop would be vectorized into the block scan and slow it down for every dialect
	idx_t DelimiterBytes(const idx_t at, const idx_t limit) const {
		const idx_t size = block_delimiter_bytes.size();
		if (at + size > limit || memcmp(buffer_handle_ptr + at + 1, block_delimiter_bytes.data() + 1, size - 1) != 0) {
			return 0;
		}
		return size;
	}

	//! The state before the last byte of a multi byte delimiter
	CSVState DelimiterPenultimateState() const {
		switch (block_delimiter_bytes.size()) {
		case 2:
			return CSVState::DELIMITER_FIRST_BYTE;
		case 3:
			return CSVState::DELIMITER_SECOND_BYTE;
		default:
			return CSVState::DELIMITER_THIRD_BYTE;
		}
	}

	//! Clears the candidate bits of the bytes [from, to) of the block starting at `pos`, fewer than 64 of them
	static void ClearCandidates(uint64_t &candidates, const idx_t pos, const idx_t from, const idx_t to) {
		candidates &= ~(((uint64_t(1) << (to - from)) - 1) << (from - pos));
	}

	//! The delimiter at `at`, `before` is the state before it
	template <class T>
	DUCKDB_BLOCK_SCAN_INLINE void BlockDelimiter(T &result, const idx_t at, const CSVState before) {
		states.states[0] = before;
		states.states[1] = CSVState::DELIMITER;
		iterator.pos.buffer_pos = at;
		if (T::CanSkipValue(result)) {
			T::SkipValue(result, at);
		} else {
			T::AddValue(result, at);
		}
	}

	//! The delimiter at `at` (the last byte of a multi byte delimiter) and the delimiters of the unprojected columns
	//! that follow it in the block, `run` at most, with one bookkeeping call. `last` is the first byte after the
	//! previous structural byte. Returns the first byte after the last consumed delimiter
	template <class T, bool MULTI_BYTE_DELIMITER, bool COMMENT>
	idx_t BlockDelimiterRun(T &result, const idx_t at, const CSVState before, const idx_t run, const idx_t last,
	                        uint64_t &candidates, const idx_t pos, const idx_t limit) {
		idx_t last_delimiter = at;
		CSVState before_last = before;
		idx_t consumed = 1;
		while (consumed < run && candidates) {
			const idx_t next = pos + CountZeros<uint64_t>::Trailing(candidates);
			if (next >= limit) {
				break;
			}
			const auto byte = static_cast<uint8_t>(buffer_handle_ptr[next]);
			if (byte != block_delimiter) {
				if (byte == '\n' || byte == '\r' || byte == block_quote || (COMMENT && byte == block_comment)) {
					break;
				}
				// a false candidate of the mask, data
				candidates &= candidates - 1;
				continue;
			}
			if (MULTI_BYTE_DELIMITER) {
				const idx_t delimiter_bytes = DelimiterBytes(next, limit);
				if (delimiter_bytes == 0) {
					break;
				}
				ClearCandidates(candidates, pos, next, next + delimiter_bytes);
				before_last = DelimiterPenultimateState();
				last_delimiter = next + delimiter_bytes - 1;
			} else {
				candidates &= candidates - 1;
				before_last = StateAfterData(CSVState::DELIMITER, last_delimiter + 1, next);
				last_delimiter = next;
			}
			consumed++;
		}
		D_ASSERT(ReplayStates(last, last_delimiter + 1).states[1] == CSVState::DELIMITER);
		D_ASSERT(ReplayStates(last, last_delimiter + 1).states[0] == before_last);
		states.states[0] = before_last;
		states.states[1] = CSVState::DELIMITER;
		iterator.pos.buffer_pos = last_delimiter;
		T::SkipValues(result, consumed, at, last_delimiter);
		return last_delimiter + 1;
	}

	//! The row end at `at`, `before` is the state before it. Returns true when the result is full
	template <class T>
	bool BlockRowEnd(T &result, const idx_t at, const CSVState before, const bool crlf, uint64_t &candidates,
	                 const idx_t pos) {
		states.states[0] = before;
		states.states[1] = crlf ? CSVState::CARRIAGE_RETURN : CSVState::RECORD_SEPARATOR;
		iterator.pos.buffer_pos = at;
		const bool full = T::CanSkipValue(result) ? T::AddRowWithoutValue(result, at) : T::AddRow(result, at);
		lines_read++;
		if (full) {
			iterator.pos.buffer_pos = at + 1;
			return true;
		}
		if (crlf) {
			states.states[0] = CSVState::CARRIAGE_RETURN;
			states.states[1] = CSVState::RECORD_SEPARATOR;
			candidates &= ~(uint64_t(1) << (at + 1 - pos));
		}
		return false;
	}

	//! The row end at `at` closes a comment, as the byte loop's record separator case does. Returns true when the
	//! result is full
	template <class T>
	bool BlockCommentEnd(T &result, const idx_t at, const bool crlf, uint64_t &candidates, const idx_t pos) {
		states.states[0] = CSVState::COMMENT;
		states.states[1] = crlf ? CSVState::CARRIAGE_RETURN : CSVState::RECORD_SEPARATOR;
		iterator.pos.buffer_pos = at;
		const bool full = T::UnsetComment(result, at);
		lines_read++;
		if (full) {
			iterator.pos.buffer_pos = at + 1;
			return true;
		}
		if (crlf) {
			states.states[0] = CSVState::CARRIAGE_RETURN;
			states.states[1] = CSVState::RECORD_SEPARATOR;
			candidates &= ~(uint64_t(1) << (at + 1 - pos));
		}
		return false;
	}

	//! The bits of a 64 bit mask at positions [from, to)
	static uint64_t BitRange(const idx_t from, const idx_t to) {
		if (from >= to || from >= 64) {
			return 0;
		}
		const uint64_t below_to = to >= 64 ? ~uint64_t(0) : (uint64_t(1) << to) - 1;
		return below_to & ~((uint64_t(1) << from) - 1);
	}

	//! The state pair right after the structural byte at `at` (a delimiter when `delimiter`, else a row end), given
	//! the structural byte `previous` before it in the same block (`none` when there is none, then the pair before
	//! `last` applies) and whether that previous byte was a delimiter
	//! `pair_consumed` is false when the line feed of a CRLF row end at `at` is left to the next chunk
	CSVStates StatesAfterStructural(const idx_t at, const bool delimiter, const idx_t previous, const bool none,
	                                const bool previous_delimiter, const idx_t last, const bool pair_consumed) const {
		CSVStates after;
		const CSVState before_previous =
		    none ? states.states[1] : (previous_delimiter ? CSVState::DELIMITER : CSVState::RECORD_SEPARATOR);
		const idx_t from = none ? last : previous + (previous_delimiter ? 1 : (block_crlf ? 2 : 1));
		after.states[0] = StateAfterData(before_previous, from, at);
		after.states[1] =
		    delimiter ? CSVState::DELIMITER : (block_crlf ? CSVState::CARRIAGE_RETURN : CSVState::RECORD_SEPARATOR);
		if (!delimiter && block_crlf && pair_consumed) {
			// the pair after the line feed of the pair
			after.states[0] = CSVState::CARRIAGE_RETURN;
			after.states[1] = CSVState::RECORD_SEPARATOR;
		}
		return after;
	}

	//! The delimiter and row end masks of a counted block and its position; empty masks mean no block
	struct CountedBlock {
		uint64_t delimiters = 0;
		uint64_t row_ends = 0;
		idx_t pos = 0;

		bool HasStructural() const {
			return (delimiters | row_ends) != 0;
		}
	};

	//! The open first value whose bytes before the block scan were checked for high bits, and the outcome
	struct CheckedValue {
		idx_t buffer_idx = DConstants::INVALID_INDEX;
		idx_t start = 0;
		idx_t end = 0;
		bool high_bit = false;
	};
	CheckedValue checked_value;

	//! The state pair after the last structural byte of the counted blocks and the position after that byte, from
	//! the last two counted blocks with structural bytes; `last` is the hand-over position before the counting. When
	//! the result is full, a CRLF row end hands over after its carriage return, as the byte path does
	void StatesAfterCountedBlocks(const CountedBlock &latest, const CountedBlock &earlier, const idx_t last,
	                              const bool full, CSVStates &after, idx_t &after_pos) const {
		const uint64_t structural = latest.delimiters | latest.row_ends;
		D_ASSERT(structural != 0);
		const idx_t at_bit = 63 - CountZeros<uint64_t>::Leading(structural);
		const bool delimiter = ((latest.delimiters >> at_bit) & 1) != 0;
		// the structural byte before it decides the state of the data between the two
		bool none = false;
		idx_t previous = 0;
		bool previous_delimiter = false;
		const uint64_t before = structural & BitRange(0, at_bit);
		if (before != 0) {
			const idx_t bit = 63 - CountZeros<uint64_t>::Leading(before);
			previous = latest.pos + bit;
			previous_delimiter = ((latest.delimiters >> bit) & 1) != 0;
		} else if (earlier.HasStructural()) {
			const idx_t bit = 63 - CountZeros<uint64_t>::Leading(earlier.delimiters | earlier.row_ends);
			previous = earlier.pos + bit;
			previous_delimiter = ((earlier.delimiters >> bit) & 1) != 0;
		} else {
			none = true;
		}
		after = StatesAfterStructural(latest.pos + at_bit, delimiter, previous, none, previous_delimiter, last, !full);
		after_pos = latest.pos + at_bit + (delimiter ? 1 : (block_crlf && !full ? 2 : 1));
	}

	//! Counts the rows of the plain 64 byte blocks from `pos` on for a scan that reads no column: a block without a
	//! quote, a stray row end byte or a non ASCII byte, whose rows all have the right number of fields, no empty
	//! line and no line over the maximum size, is counted from its delimiter and row end masks without a visit to
	//! its other bytes. Stops at the first block or row that needs the byte by byte path and leaves `states`, `last`
	//! and the result positioned for it. Returns the position reached; `full` is set when the result is full
	template <class T>
	idx_t CountRowsInPlainBlocks(T &result, idx_t pos, const idx_t to_pos, idx_t &last, bool &full) {
		const auto buffer = buffer_handle_ptr;
		const idx_t columns = result.number_of_columns;
		const idx_t max_line_size = state_machine->options.maximum_line_size.GetValue();
		const idx_t row_end_bytes = block_crlf ? 2 : 1;
		if (result.current_errors.IsErrorInLine() || result.quoted_new_line) {
			// the open row already has an error on record, or a quoted newline waits for the byte path's check of
			// the next row: the byte path finishes and reports it
			return pos;
		}
		if (result.cur_col_id == 0 && result.last_position.buffer_pos < pos) {
			// the first value of the open row began before `pos`, in bytes the byte path has not validated yet; the
			// bytes checked are remembered, so a long value is checked once and not once per block
			if (result.last_position.buffer_idx != iterator.pos.buffer_idx) {
				return pos;
			}
			idx_t from = result.last_position.buffer_pos;
			if (checked_value.buffer_idx == iterator.pos.buffer_idx && checked_value.start == from) {
				if (checked_value.high_bit) {
					return pos;
				}
				from = checked_value.end;
			} else {
				checked_value = {iterator.pos.buffer_idx, from, from, false};
			}
			for (idx_t i = from; i < pos; i++) {
				if (static_cast<uint8_t>(buffer[i]) & 0x80) {
					checked_value.high_bit = true;
					return pos;
				}
			}
			checked_value.end = pos;
		}
		const idx_t buffer_size = cur_buffer_handle->actual_size;
		// the row end byte is the carriage return of a pair; a line feed is then the other byte, exact mask needed
		const uint8_t row_end_byte = block_cr || block_crlf ? '\r' : '\n';
		const uint8_t other_byte = block_cr || block_crlf ? '\n' : '\r';
		// the open row: the fields it has done, its start (the hand-over position, when no field is done yet) and
		// the row end before it for the line size, when that lies in this buffer
		idx_t fields_done = result.cur_col_id;
		idx_t row_start_pos = last;
		bool have_previous_end = result.current_line_position.end.buffer_idx == iterator.pos.buffer_idx;
		idx_t previous_end = have_previous_end ? result.current_line_position.end.buffer_pos : 0;
		// the last two counted blocks with structural bytes, for the states at the hand-over
		CountedBlock latest;
		CountedBlock earlier;
#ifdef DEBUG
		const idx_t last_before = last;
#endif
		// whether the byte path resumes at the hand-over position (after counted rows) or at the block reached
		bool resume_at_last = false;
		bool stop = false;
		while (pos + SwarBlock::SIZE <= to_pos && pos + SwarBlock::SIZE <= buffer_size) {
			const auto window = const_data_ptr_cast(buffer + pos);
			uint64_t delimiters;
			uint64_t row_ends;
			uint64_t line_feeds;
			if (block_crlf) {
				// a non ASCII byte or a quote: the byte path's block
				if (SwarBlock::HasHighBitOrBytes(window, block_quote, block_quote)) {
					break;
				}
				SwarBlock::RowCountMasks<true>(window, block_delimiter, row_end_byte, other_byte, delimiters, row_ends,
				                               line_feeds);
				// every carriage return must pair with a line feed inside the block, and every line feed with one
				const uint64_t pairs = row_ends & (line_feeds >> 1);
				if ((row_ends & ~pairs) != 0 || (line_feeds & ~(pairs << 1)) != 0) {
					break;
				}
				row_ends = pairs;
			} else {
				// a non ASCII byte, a quote or the other row end byte: the byte path's block
				if (SwarBlock::HasHighBitOrBytes(window, block_quote, other_byte)) {
					break;
				}
				SwarBlock::RowCountMasks<false>(window, block_delimiter, row_end_byte, other_byte, delimiters, row_ends,
				                                line_feeds);
			}
			// the rows ending in this block
			uint64_t pending = row_ends;
			idx_t row_start = 0;
			idx_t rows = 0;
			idx_t last_row_end = 0;
			while (pending != 0) {
				const idx_t end = CountZeros<uint64_t>::Trailing(pending);
				pending &= pending - 1;
				const idx_t fields = fields_done + SwarWord::CountSetBits(delimiters & BitRange(row_start, end)) + 1;
				const idx_t end_pos = pos + end;
				// an empty line is a row end at the start of its row; the line size is the byte path's, from the end
				// of the last row that was not an empty line
				const bool empty_line = fields_done == 0 && end_pos == row_start_pos;
				idx_t line_size;
				if (have_previous_end) {
					line_size = end_pos - previous_end;
				} else {
					// the row end before this row is in an earlier buffer
					line_size = LinePosition(iterator.pos.buffer_idx, end_pos, result.buffer_size) -
					            result.current_line_position.end;
				}
				if (fields != columns || empty_line || line_size > max_line_size) {
					// a row with another field count, an empty line or an oversized line: the byte path reports it
					stop = true;
					break;
				}
				rows++;
				last_row_end = end;
				row_start = end + row_end_bytes;
				row_start_pos = end_pos + row_end_bytes;
				fields_done = 0;
				have_previous_end = true;
				previous_end = end_pos;
				if (static_cast<idx_t>(result.number_of_rows) + rows >= result.result_size) {
					full = true;
					break;
				}
			}
			if (rows > 0) {
				lines_read += rows;
				T::AddCountedRows(result, rows, pos + last_row_end, pos + last_row_end + row_end_bytes);
			}
			// the delimiters after the last row end add fields to the open row; a row that reaches the declared width
			// before its end has surplus fields, which the byte path checks value by value
			const idx_t trailing_fields = SwarWord::CountSetBits(delimiters & BitRange(row_start, SwarBlock::SIZE));
			if (fields_done + trailing_fields >= columns) {
				stop = true;
			}
			if (stop || full) {
				if (rows > 0) {
					// the byte path takes over after the last counted row end
					if (latest.HasStructural()) {
						earlier = latest;
					}
					latest = {delimiters & BitRange(0, last_row_end + 1), row_ends & BitRange(0, last_row_end + 1),
					          pos};
					resume_at_last = true;
				}
				break;
			}
			// the whole block is counted, the open row carries its fields into the next block
			fields_done += trailing_fields;
			if ((delimiters | row_ends) != 0) {
				earlier = latest;
				latest = {delimiters, row_ends, pos};
			}
			pos += SwarBlock::SIZE;
		}
		if (latest.HasStructural()) {
			CSVStates after;
			idx_t after_pos;
			StatesAfterCountedBlocks(latest, earlier, last, full, after, after_pos);
#ifdef DEBUG
			const CSVStates replay = ReplayStates(last_before, after_pos);
			D_ASSERT(replay.states[0] == after.states[0] && replay.states[1] == after.states[1]);
#endif
			states = after;
			last = after_pos;
			result.cur_col_id = fields_done;
			result.last_position = {iterator.pos.buffer_idx, last, result.buffer_size};
		}
		if (resume_at_last) {
			iterator.pos.buffer_pos = last;
			return last;
		}
		// the bytes between the hand-over position and the block reached are data
		D_ASSERT(ReplayStates(last, pos).states[1] == StateAfterData(states.states[1], last, pos));
		return pos;
	}

	//! Scans unquoted fields and quoted values in their canonical form, and preserves the states when handing back
	//! to Process. Returns true when the result is full. Repeated SetQuoted calls may be skipped because the setter
	//! is idempotent. MULTI_BYTE_DELIMITER and COMMENT are the dialect's, so dialects without them pay nothing for
	//! them; SKIP_RUNS is set for scans with unprojected columns, so scans reading every column keep the plain
	//! delimiter path; COUNT_ROWS is set for scans that read no column, whose plain blocks are counted from masks
	template <class T, bool MULTI_BYTE_DELIMITER, bool COMMENT, bool SKIP_RUNS, bool COUNT_ROWS>
	DUCKDB_BLOCK_SCAN_ALIGNED bool ProcessBlocks(T &result, const idx_t to_pos) {
		const auto buffer = buffer_handle_ptr;
		// the first byte not consumed, and the first byte after the last structural or special byte
		idx_t pos = iterator.pos.buffer_pos;
		idx_t last = pos;
		bool quoted = false;
		// inside a comment only a row end matters, `comment_before` is the state before the comment byte
		bool comment = false;
		CSVState comment_before = CSVState::NOT_SET;
		uint64_t candidates;
		idx_t block_end;
		while (pos < to_pos) {
			if constexpr (COUNT_ROWS) {
				if (!quoted) {
					bool full = false;
					pos = CountRowsInPlainBlocks(result, pos, to_pos, last, full);
					if (full) {
						return true;
					}
					if (pos >= to_pos) {
						break;
					}
				}
			}
			if (!skipper.BlockCandidates(pos, candidates, block_end)) {
				break;
			}
			const idx_t limit = MinValue<idx_t>(block_end, to_pos);
			while (candidates) {
				const idx_t at = pos + CountZeros<uint64_t>::Trailing(candidates);
				if (at >= limit) {
					break;
				}
				candidates &= candidates - 1;
				const auto byte = static_cast<uint8_t>(buffer[at]);
				if (COMMENT && comment) {
					const idx_t row_end_bytes = RowEndBytes(byte, at, limit);
					if (row_end_bytes == 0) {
						if (byte == '\n' || byte == '\r') {
							return HandOverComment(at, last, comment_before);
						}
						continue;
					}
					D_ASSERT(ReplayStates(last, at + 1).states[0] == CSVState::COMMENT);
					D_ASSERT(ReplayStates(last, at + 1).states[1] ==
					         (row_end_bytes == 2 ? CSVState::CARRIAGE_RETURN : CSVState::RECORD_SEPARATOR));
					if (BlockCommentEnd(result, at, row_end_bytes == 2, candidates, pos)) {
						return true;
					}
					comment = false;
					last = at + row_end_bytes;
					continue;
				}
				if (quoted) {
					if (byte == '\n' || byte == '\r') {
						// QUOTED and QUOTED_NEW_LINE alternate on newline bytes inside the quotes
						SetQuotedStatesBefore(at, last);
						const bool new_line_state = states.states[1] == CSVState::QUOTED;
						states.states[0] = states.states[1];
						states.states[1] = new_line_state ? CSVState::QUOTED_NEW_LINE : CSVState::QUOTED;
						iterator.pos.buffer_pos = at;
						if (new_line_state) {
							T::QuotedNewLine(result);
						} else {
							ever_quoted = true;
							T::SetQuoted(result, at);
						}
						last = at + 1;
						continue;
					}
					if (byte != block_quote) {
						continue;
					}
					if (at + 1 >= limit) {
						return HandOverQuoted(at, last);
					}
					const auto next = static_cast<uint8_t>(buffer[at + 1]);
					const bool escape_pair = block_escape_is_quote && next == block_quote;
					const idx_t delimiter_bytes = next != block_delimiter ? 0
					                              : MULTI_BYTE_DELIMITER  ? DelimiterBytes(at + 1, limit)
					                                                      : 1;
					const idx_t row_end_bytes = RowEndBytes(next, at + 1, limit);
					if (!escape_pair && delimiter_bytes == 0 && row_end_bytes == 0) {
						return HandOverQuoted(at, last);
					}
					SetQuotedStatesBefore(at, last);
					states.states[0] = states.states[1];
					states.states[1] = CSVState::UNQUOTED;
					iterator.pos.buffer_pos = at;
					T::SetUnquoted(result);
					candidates &= ~(uint64_t(1) << (at + 1 - pos));
					if (escape_pair) {
						states.states[0] = CSVState::UNQUOTED;
						states.states[1] = CSVState::QUOTED;
						iterator.pos.buffer_pos = at + 1;
						ever_escaped = true;
						T::SetEscaped(result);
						ever_quoted = true;
						T::SetQuoted(result, at + 1);
						last = at + 2;
						continue;
					}
					quoted = false;
					if (delimiter_bytes != 0) {
						if (MULTI_BYTE_DELIMITER) {
							ClearCandidates(candidates, pos, at + 2, at + 1 + delimiter_bytes);
						}
						BlockDelimiter(result, at + delimiter_bytes,
						               MULTI_BYTE_DELIMITER ? DelimiterPenultimateState() : CSVState::UNQUOTED);
						last = at + 1 + delimiter_bytes;
						continue;
					}
					if (BlockRowEnd(result, at + 1, CSVState::UNQUOTED, row_end_bytes == 2, candidates, pos)) {
						return true;
					}
					last = at + 1 + row_end_bytes;
					continue;
				}
				const auto before = StateAfterData(states.states[1], last, at);
				if (byte == block_delimiter) {
					if (MULTI_BYTE_DELIMITER) {
						const idx_t delimiter_bytes = DelimiterBytes(at, limit);
						if (delimiter_bytes == 0) {
							// part of a multi byte delimiter, the byte loop walks the delimiter byte states
							return HandOver(at, last);
						}
						D_ASSERT(ReplayStates(last, at + delimiter_bytes).states[1] == CSVState::DELIMITER);
						D_ASSERT(ReplayStates(last, at + delimiter_bytes).states[0] == DelimiterPenultimateState());
						ClearCandidates(candidates, pos, at + 1, at + delimiter_bytes);
						const idx_t run = SKIP_RUNS ? T::SkippableRun(result, at + delimiter_bytes - 1) : 0;
						if (run > 0) {
							last = BlockDelimiterRun<T, true, COMMENT>(result, at + delimiter_bytes - 1,
							                                           DelimiterPenultimateState(), run, last,
							                                           candidates, pos, limit);
						} else {
							BlockDelimiter(result, at + delimiter_bytes - 1, DelimiterPenultimateState());
							last = at + delimiter_bytes;
						}
						continue;
					}
					D_ASSERT(ReplayStates(last, at + 1).states[1] == CSVState::DELIMITER);
					D_ASSERT(ReplayStates(last, at + 1).states[0] == before);
					const idx_t run = SKIP_RUNS ? T::SkippableRun(result, at) : 0;
					if (run > 0) {
						last =
						    BlockDelimiterRun<T, false, COMMENT>(result, at, before, run, last, candidates, pos, limit);
					} else {
						BlockDelimiter(result, at, before);
						last = at + 1;
					}
					continue;
				}
				if (COMMENT && byte == block_comment) {
					D_ASSERT(ReplayStates(last, at + 1).states[1] == CSVState::COMMENT);
					D_ASSERT(ReplayStates(last, at + 1).states[0] == before);
					states.states[0] = before;
					states.states[1] = CSVState::COMMENT;
					iterator.pos.buffer_pos = at;
					T::SetComment(result, at);
					comment = true;
					comment_before = before;
					last = at + 1;
					continue;
				}
				if (block_quote != '\0' && byte == block_quote) {
					if (before == CSVState::STANDARD) {
						// a quote inside an unquoted value is data
						continue;
					}
					D_ASSERT(ReplayStates(last, at + 1).states[1] == CSVState::QUOTED);
					states.states[0] = before;
					states.states[1] = CSVState::QUOTED;
					iterator.pos.buffer_pos = at;
					ever_quoted = true;
					T::SetQuoted(result, at);
					quoted = true;
					last = at + 1;
					continue;
				}
				const idx_t row_end_bytes = RowEndBytes(byte, at, limit);
				if (row_end_bytes == 0) {
					if (byte == '\n' || byte == '\r') {
						return HandOver(at, last);
					}
					// a false candidate of the mask, data
					continue;
				}
				if (before == CSVState::RECORD_SEPARATOR || before == CSVState::NOT_SET) {
					// an empty line
					return HandOver(at, last);
				}
				D_ASSERT(ReplayStates(last, at + 1).states[0] == before);
				D_ASSERT(ReplayStates(last, at + 1).states[1] ==
				         (row_end_bytes == 2 ? CSVState::CARRIAGE_RETURN : CSVState::RECORD_SEPARATOR));
				if (BlockRowEnd(result, at, before, row_end_bytes == 2, candidates, pos)) {
					return true;
				}
				last = at + row_end_bytes;
			}
			pos = limit;
		}
		if (COMMENT && comment) {
			return HandOverComment(pos, last, comment_before);
		}
		return quoted ? HandOverQuoted(pos, last) : HandOver(pos, last);
	}

	//! Leaves the block scan at `at`, with the states before it
	bool HandOver(const idx_t at, const idx_t last) {
		SetStatesBefore(at, last);
		iterator.pos.buffer_pos = at;
		return false;
	}

	//! The block scan of the dialect, with or without the skipping of unprojected column runs; the row counting from
	//! masks exists for the plain dialect only
	template <class T, bool SKIP_RUNS, bool COUNT_ROWS>
	bool ProcessBlocksOfDialect(T &result, const idx_t to_pos) {
		if (block_comment != '\0') {
			return block_multi_byte_delimiter ? ProcessBlocks<T, true, true, SKIP_RUNS, false>(result, to_pos)
			                                  : ProcessBlocks<T, false, true, SKIP_RUNS, false>(result, to_pos);
		}
		return block_multi_byte_delimiter ? ProcessBlocks<T, true, false, SKIP_RUNS, false>(result, to_pos)
		                                  : ProcessBlocks<T, false, false, SKIP_RUNS, COUNT_ROWS>(result, to_pos);
	}

	//! Process one chunk
	template <class T>
	void Process(T &result) {
		idx_t to_pos;
		const bool has_escaped_value = state_machine->dialect_options.state_machine_options.escape != '\0';
		const idx_t start_pos = iterator.pos.buffer_pos;
		if (iterator.IsBoundarySet()) {
			to_pos = iterator.GetEndPos();
			if (to_pos > cur_buffer_handle->actual_size) {
				to_pos = cur_buffer_handle->actual_size;
			}
		} else {
			to_pos = cur_buffer_handle->actual_size;
		}
		skipper.SetBuffer(*cur_buffer_handle);
		while (iterator.pos.buffer_pos < to_pos) {
			if (T::BLOCK_SCAN && block_scan && BlockScanPossible(result)) {
				bool full;
				if constexpr (T::CAN_COUNT_ROWS) {
					full = T::CountsRowsOnly(result) ? ProcessBlocksOfDialect<T, true, true>(result, to_pos)
					       : T::SkipsRuns(result)    ? ProcessBlocksOfDialect<T, true, false>(result, to_pos)
					                                 : ProcessBlocksOfDialect<T, false, false>(result, to_pos);
				} else {
					full = T::SkipsRuns(result) ? ProcessBlocksOfDialect<T, true, false>(result, to_pos)
					                            : ProcessBlocksOfDialect<T, false, false>(result, to_pos);
				}
				if (full) {
					bytes_read = iterator.pos.buffer_pos - start_pos;
					return;
				}
				if (iterator.pos.buffer_pos >= to_pos) {
					break;
				}
			}
			state_machine->Transition(states, buffer_handle_ptr[iterator.pos.buffer_pos]);
			switch (states.states[1]) {
			case CSVState::INVALID:
				T::InvalidState(result);
				iterator.pos.buffer_pos++;
				bytes_read = iterator.pos.buffer_pos - start_pos;
				return;
			case CSVState::RECORD_SEPARATOR:
				if (states.states[0] == CSVState::RECORD_SEPARATOR || states.states[0] == CSVState::NOT_SET) {
					if (T::EmptyLine(result, iterator.pos.buffer_pos)) {
						iterator.pos.buffer_pos++;
						bytes_read = iterator.pos.buffer_pos - start_pos;
						lines_read++;
						return;
					}
					lines_read++;

				} else if (states.states[0] != CSVState::CARRIAGE_RETURN) {
					if (T::IsCommentSet(result)) {
						if (T::UnsetComment(result, iterator.pos.buffer_pos)) {
							iterator.pos.buffer_pos++;
							bytes_read = iterator.pos.buffer_pos - start_pos;
							lines_read++;
							return;
						}
					} else {
						if (T::AddRow(result, iterator.pos.buffer_pos)) {
							iterator.pos.buffer_pos++;
							bytes_read = iterator.pos.buffer_pos - start_pos;
							lines_read++;
							return;
						}
					}
					lines_read++;
				}
				iterator.pos.buffer_pos++;
				break;
			case CSVState::CARRIAGE_RETURN:
				if (states.states[0] == CSVState::RECORD_SEPARATOR || states.states[0] == CSVState::NOT_SET) {
					if (T::EmptyLine(result, iterator.pos.buffer_pos)) {
						iterator.pos.buffer_pos++;
						bytes_read = iterator.pos.buffer_pos - start_pos;
						lines_read++;
						return;
					}
				} else if (states.states[0] != CSVState::CARRIAGE_RETURN) {
					if (T::IsCommentSet(result)) {
						if (T::UnsetComment(result, iterator.pos.buffer_pos)) {
							iterator.pos.buffer_pos++;
							bytes_read = iterator.pos.buffer_pos - start_pos;
							lines_read++;
							return;
						}
					} else {
						if (T::AddRow(result, iterator.pos.buffer_pos)) {
							iterator.pos.buffer_pos++;
							bytes_read = iterator.pos.buffer_pos - start_pos;
							lines_read++;
							return;
						}
					}
				}
				iterator.pos.buffer_pos++;
				lines_read++;
				break;
			case CSVState::DELIMITER:
				T::AddValue(result, iterator.pos.buffer_pos);
				iterator.pos.buffer_pos++;
				break;
			case CSVState::QUOTED: {
				if ((states.states[0] == CSVState::UNQUOTED || states.states[0] == CSVState::MAYBE_QUOTED) &&
				    has_escaped_value) {
					ever_escaped = true;
					T::SetEscaped(result);
				}
				if ((states.states[0] == CSVState::ESCAPE || states.states[0] == CSVState::ESCAPED_RETURN ||
				     states.states[0] == CSVState::UNQUOTED_ESCAPE) &&
				    (buffer_handle_ptr[iterator.pos.buffer_pos] ==
				         state_machine->dialect_options.state_machine_options.quote.GetValue() ||
				     !state_machine->dialect_options.state_machine_options.strict_mode.GetValue())) {
					// We only set the ever escaped variable if this is either a quote char OR strict mode is off
					ever_escaped = true;
					if (states.states[0] == CSVState::UNQUOTED_ESCAPE) {
						used_unstrictness = true;
					}
				}
				ever_quoted = true;
				T::SetQuoted(result, iterator.pos.buffer_pos);
				iterator.pos.buffer_pos++;
				skipper.SkipToStop(state_machine->transition_array.skip_quoted, to_pos, iterator.pos.buffer_pos);
			} break;
			case CSVState::UNQUOTED: {
				if (states.states[0] == CSVState::MAYBE_QUOTED) {
					ever_escaped = true;
					T::SetEscaped(result);
				}
				T::SetUnquoted(result);
				iterator.pos.buffer_pos++;
				break;
			}
			case CSVState::ESCAPE:
			case CSVState::ESCAPED_RETURN:
				T::SetEscaped(result);
				iterator.pos.buffer_pos++;
				break;
			case CSVState::UNQUOTED_ESCAPE:
				T::SetEscaped(result);
				iterator.pos.buffer_pos++;
				used_unstrictness = true;
				break;
			case CSVState::STANDARD:
				iterator.pos.buffer_pos++;
				skipper.SkipToStop(state_machine->transition_array.skip_standard, to_pos, iterator.pos.buffer_pos);
				break;
			case CSVState::QUOTED_NEW_LINE:
				T::QuotedNewLine(result);
				iterator.pos.buffer_pos++;
				break;
			case CSVState::COMMENT:
				T::SetComment(result, iterator.pos.buffer_pos);
				iterator.pos.buffer_pos++;
				skipper.SkipToStop(state_machine->transition_array.skip_comment, to_pos, iterator.pos.buffer_pos);
				break;
			default:
				iterator.pos.buffer_pos++;
				break;
			}
		}
		bytes_read = iterator.pos.buffer_pos - start_pos;
	}

	//! Finalizes the process of the chunk
	virtual void FinalizeChunkProcess();

	//! Internal function for parse chunk
	template <class T>
	void ParseChunkInternal(T &result) {
		if (iterator.done) {
			return;
		}
		if (!initialized) {
			Initialize();
			initialized = true;
		}
		if (!iterator.done && cur_buffer_handle) {
			Process(result);
		}
		FinalizeChunkProcess();
	}
};

} // namespace duckdb

#undef DUCKDB_BLOCK_SCAN_ALIGNED
