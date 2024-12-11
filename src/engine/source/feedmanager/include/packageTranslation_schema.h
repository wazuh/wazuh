// This file was generated from ./schemas/packageTranslation.fbs , do not modify 
#ifndef packageTranslation_HEADER
#define packageTranslation_HEADER
auto constexpr packageTranslation_SCHEMA = R"(namespace NSVulnerabilityScanner; enum Action : byte { replace_vendor = 0, replace_product, replace_vendor_if_matches, replace_product_if_matches, set_version_if_matches, replace_sw_edition_if_product_matches, replace_msu_name_if_version_matches, ignore, check_hotfix, replace_msu_name, set_version_if_product_matches, set_targethw_if_product_matches, set_version_only_if_product_matches, set_targethw_only_if_product_matches, set_update_if_product_matches, set_update_only_if_product_matches } table SourceFields { vendor: string; product: string; version: string; update: string; target_hw: string; } table TranslationFields { vendor: string; product: string; version: string; update: string; msu_name: string; sw_edition: string; } table TranslationEntry { action:[Action]; source:SourceFields; target:[string]; translation:[TranslationFields]; } root_type TranslationEntry;)" ;
#endif // packageTranslation_HEADER
 
