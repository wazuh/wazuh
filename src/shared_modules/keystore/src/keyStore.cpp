#include "keyStore.hpp"
#include "evpHelper.hpp"
#include "loggerHelper.h"
#include "rocksDBWrapper.hpp"

// Database constants, based on the keystore path.
constexpr auto DATABASE_PATH {"queue/keystore"};

// Keystore constants.
// KS_VERSION is the current version of the keystore. Used to identify the version of the keystore in the database.
// KS_VERSION_FIELD is the field used to store the version of the keystore in the database.
constexpr auto KS_VERSION {"2"};
constexpr auto KS_VERSION_FIELD {"version"};

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
};

// Stamp the keystore format version. Pre-versioning keystores are not migrated: the manager is not
// upgraded in place across the 4.x -> 5.x boundary, so no legacy keystore reaches this code. The
// version field is kept so future format changes can key off it.
static void upgrade(Utils::RocksDBWrapper& keystoreDB, const std::string& columnFamily)
{
    std::string versionValue;

    if (!keystoreDB.get(KS_VERSION_FIELD, versionValue, columnFamily) || versionValue != KS_VERSION)
    {
        keystoreDB.put(KS_VERSION_FIELD, KS_VERSION, columnFamily);
    }
}

void Keystore::put(const std::string& columnFamily, const std::string& key, const std::string& value)
{
    std::vector<char> encryptedValue;

    EVPHelper().encryptAES256(value, encryptedValue);

    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }

    // Ensure the keystore version field is stamped before inserting.
    upgrade(keystoreDB, columnFamily);

    // Insert the key-value pair using AES encryption.
    keystoreDB.put(key, rocksdb::Slice(encryptedValue.data(), encryptedValue.size()), columnFamily);
}

/**
 * Get the key value in the specified column family.
 *
 * @param columnFamily The target column family.
 * @param key The key to be inserted or updated.
 * @param value The corresponding value to be returned.
 */
void Keystore::get(const std::string& columnFamily, const std::string& key, std::string& value)
{
    std::string encryptedValue;

    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }

    // Ensure the keystore version field is stamped before reading.
    upgrade(keystoreDB, columnFamily);

    // Get the key-value pair using AES decryption.
    if (keystoreDB.get(key, encryptedValue, columnFamily))
    {
        std::vector<char> encryptedValueVec(encryptedValue.begin(), encryptedValue.end());
        EVPHelper().decryptAES256(encryptedValueVec, value);
    }
}

/**
 * Get the key value in the specified column family.
 *
 * @param columnFamily The target column family.
 * @param key The key to be inserted or updated.
 * @return The corresponding value to be returned.
 */
std::string Keystore::get(const std::string& columnFamily, const std::string& key)
{
    std::string value;
    std::string encryptedValue;

    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }

    // Ensure the keystore version field is stamped before reading.
    upgrade(keystoreDB, columnFamily);

    // Get the key-value pair using AES decryption.
    if (keystoreDB.get(key, encryptedValue, columnFamily))
    {
        std::vector<char> encryptedValueVec(encryptedValue.begin(), encryptedValue.end());
        EVPHelper().decryptAES256(encryptedValueVec, value);
    }
    return value;
}
