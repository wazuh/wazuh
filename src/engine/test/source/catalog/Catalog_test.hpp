#ifndef __CATALOG_TEST_H__
#define __CATALOG_TEST_H__

#include <gtest/gtest.h>
#include <string>

#include "catalog/Catalog.hpp"
#include "Catalog_json_assets.hpp"
#include "rapidjson/error/en.h"

/**
 * @brief Fake storage driver
 * @details This class is used to test the Catalog class
 */
class fakeStorage : public StorageDriverInterface
{

    private:
        bool thwo_exception = false;
        bool return_empty = false;

    public:
        fakeStorage() = default;
        ~fakeStorage() = default;

        std::vector<std::string_view> getAssetList(const AssetType type) override
        {
            std::vector<std::string_view> assets;

            if (!return_empty)
            {
                assets.push_back("asset_1");
                assets.push_back("asset_2");
                assets.push_back("asset_3");
            }

            return assets;
        }

        std::string getAsset(const AssetType type, std::string_view assetName) override
        {

            std::string asset;

            if (this->return_empty)
            {
                return asset;

            }
            else if (this->thwo_exception)
            {
                // #TODO throw exception
                ;;
            }

            switch (type)
            {
                case AssetType::Decoder:
                    asset.append(json_decoder_valid);
                    break;

                case AssetType::Rule:
                    // #TODO add rule assets
                    ;;//raw_asset = rule_asset;
                    break;

                case AssetType::Output:
                    // #TODO add output assets
                    ;;//raw_asset = output_asset;
                    break;

                case AssetType::Filter:
                    // #TODO add filter assets
                    ;;//raw_asset = filter_asset;
                    break;

                case AssetType::Schemas:
                    asset.append(json_schema_decoder);
                    break;

                case AssetType::Environments:
                default:
                    // #TODO Error
                    break;
            }

            return asset;
        }

        // Methods to set configuration for the fake storage to test the Catalog class

        /** @brief Set the exception flag */
        void set_exception(bool exception)
        {
            this->thwo_exception = exception;
        }

        /** @brief Set the return empty flag */
        void set_return_empty(bool return_empty)
        {
            this->return_empty = return_empty;
        }
};

#endif // __CATALOG_TEST_H__
