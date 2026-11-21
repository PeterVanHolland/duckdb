#include "catch.hpp"
#include "test_helpers.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"

using namespace duckdb;

namespace {

//! Simulate an extension catalog without a main schema, the attach path names its default schema or none
class DefaultSchemaCatalog : public DuckCatalog {
public:
	DefaultSchemaCatalog(AttachedDatabase &db, optional<Identifier> default_schema_p)
	    : DuckCatalog(db), default_schema(std::move(default_schema_p)) {
	}

	optional<Identifier> GetDefaultSchema() const override {
		return default_schema;
	}

	optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction transaction, const EntryLookupInfo &lookup,
	                                              OnEntryNotFound if_not_found) override {
		if (lookup.GetEntryIdentifier() == Identifier(DEFAULT_SCHEMA)) {
			if (if_not_found == OnEntryNotFound::THROW_EXCEPTION) {
				throw CatalogException("Schema with name %s does not exist!", DEFAULT_SCHEMA);
			}
			return nullptr;
		}
		return DuckCatalog::LookupSchema(transaction, lookup, if_not_found);
	}

private:
	optional<Identifier> default_schema;
};

struct DefaultSchemaStorageExtension : StorageExtension {
	DefaultSchemaStorageExtension() {
		attach = [](optional_ptr<StorageExtensionInfo>, ClientContext &, AttachedDatabase &db, const string &,
		            AttachInfo &info, AttachOptions &) -> unique_ptr<Catalog> {
			optional<Identifier> default_schema;
			if (info.path != "none") {
				default_schema = Identifier(info.path);
			}
			info.path = IN_MEMORY_PATH;
			return make_uniq_base<Catalog, DefaultSchemaCatalog>(db, std::move(default_schema));
		};
		create_transaction_manager = [](optional_ptr<StorageExtensionInfo>, AttachedDatabase &db,
		                                Catalog &) -> unique_ptr<TransactionManager> {
			return make_uniq<DuckTransactionManager>(db);
		};
	}
};

} // namespace

TEST_CASE("Dropping the current schema of a catalog without a main schema", "[api][catalog]") {
	DBConfig config;
	StorageExtension::Register(config, "default_schema_test", make_shared_ptr<DefaultSchemaStorageExtension>());
	DuckDB db(nullptr, &config);
	Connection con(db);
	REQUIRE_NO_FAIL(con.Query("ATTACH 'public' AS pg (TYPE default_schema_test)"));
	REQUIRE_NO_FAIL(con.Query("CREATE SCHEMA pg.public"));
	REQUIRE_NO_FAIL(con.Query("CREATE SCHEMA pg.other"));

	// dropping the current schema moves the default to the default schema of the catalog
	REQUIRE_NO_FAIL(con.Query("USE pg.other"));
	REQUIRE_NO_FAIL(con.Query("DROP SCHEMA other"));
	auto result = con.Query("SELECT current_catalog(), current_schema()");
	REQUIRE(CHECK_COLUMN(result, 0, {Value("pg")}));
	REQUIRE(CHECK_COLUMN(result, 1, {Value("public")}));

	// dropping the default schema itself keeps the catalog, unqualified names fail until it exists again
	REQUIRE_NO_FAIL(con.Query("DROP SCHEMA public CASCADE"));
	result = con.Query("SELECT current_catalog(), current_schema()");
	REQUIRE(CHECK_COLUMN(result, 0, {Value("pg")}));
	REQUIRE(CHECK_COLUMN(result, 1, {Value("public")}));
	REQUIRE_FAIL(con.Query("CREATE TABLE t(i INTEGER)"));
	REQUIRE_NO_FAIL(con.Query("CREATE SCHEMA public"));
	REQUIRE_NO_FAIL(con.Query("CREATE TABLE t AS SELECT 42 AS i"));
	result = con.Query("SELECT database_name, schema_name FROM duckdb_tables() WHERE table_name = 't'");
	REQUIRE(CHECK_COLUMN(result, 0, {Value("pg")}));
	REQUIRE(CHECK_COLUMN(result, 1, {Value("public")}));

	// a catalog without a default schema cannot stay the default
	REQUIRE_NO_FAIL(con.Query("ATTACH 'none' AS nd (TYPE default_schema_test)"));
	REQUIRE_NO_FAIL(con.Query("CREATE SCHEMA nd.s1"));
	REQUIRE_NO_FAIL(con.Query("USE nd.s1"));
	REQUIRE_NO_FAIL(con.Query("DROP SCHEMA s1"));
	result = con.Query("SELECT current_catalog(), current_schema()");
	REQUIRE(CHECK_COLUMN(result, 0, {Value("memory")}));
	REQUIRE(CHECK_COLUMN(result, 1, {Value("main")}));

	REQUIRE_NO_FAIL(con.Query("DETACH pg"));
	REQUIRE_NO_FAIL(con.Query("DETACH nd"));
}
