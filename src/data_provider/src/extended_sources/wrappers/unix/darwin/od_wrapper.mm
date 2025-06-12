/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#import <OpenDirectory/OpenDirectory.h>
#import <Foundation/Foundation.h>
#include "od_wrapper.hpp"
#include "json.hpp"

namespace od
{

    void genEntries(const std::string& record_type,
                    const std::string* record,
                    std::map<std::string, bool>& names)
    {
        @autoreleasepool
        {
            ODSession* session = [ODSession defaultSession];
            NSError* err = nil;

            ODNode* root = [ODNode nodeWithSession:session
                                   name:@"/Local/Default"
                                   error:&err];

            if (err != nil) return;

            NSString* recordType = [NSString stringWithUTF8String:record_type.c_str()];
            NSString* attribute = [recordType isEqualToString:(__bridge NSString*)kODRecordTypeGroups]
            ? (__bridge NSString*)kODAttributeTypePrimaryGroupID
            : (__bridge NSString*)kODAttributeTypeUniqueID;

            NSString* queryValue = record ? [NSString stringWithUTF8String:record->c_str()] : nil;

            ODQuery* query = [ODQuery queryWithNode:root
                                      forRecordTypes:recordType
                                      attribute:attribute
                                      matchType:kODMatchEqualTo
                                      queryValues:queryValue
                                      returnAttributes:kODAttributeTypeAllTypes
                                      maximumResults:0
                                      error:&err];

            if (err != nil) return;

            NSArray* results = [query resultsAllowingPartial:NO error:&err];

            if (err != nil) return;

            for (ODRecord * re in results)
            {
                bool isHidden = false;
                NSArray* isHiddenValue = [re valuesForAttribute:@"dsAttrTypeNative:IsHidden" error:nil];

                if ([isHiddenValue count] >= 1)
                {
                    NSString* val = [isHiddenValue[0] description];
                    isHidden = ([val isEqualToString:@"1"] || [val isEqualToString:@"true"]);
                }

                std::string name([[re recordName] UTF8String]);
                names[name] = isHidden;
            }
        }
    }

    void genAccountPolicyData(const std::string& uid, nlohmann::json& policyData)
    {
        ODSession* s = [ODSession defaultSession];
        NSError* err = nullptr;

        policyData =
        {
            {"creation_time", nullptr},
            {"failed_login_count", nullptr},
            {"failed_login_timestamp", nullptr},
            {"password_last_set_time", nullptr}
        };

        ODNode* root = [ODNode nodeWithSession:s name:@"/Local/Default" error:&err];

        if (err != nullptr)
        {
            return;
        }

        ODQuery* q =
            [ODQuery queryWithNode:root
                     forRecordTypes:kODRecordTypeUsers
                     attribute:kODAttributeTypeUniqueID
                     matchType:kODMatchEqualTo
                     queryValues:[NSString stringWithFormat:@"%s", uid.c_str()]
                     returnAttributes:@"dsAttrTypeNative:accountPolicyData"
                     maximumResults:0
                     error:&err];

        if (err != nullptr)
        {
            return;
        }

        NSArray* od_results = [q resultsAllowingPartial:NO error:&err];

        if (err != nullptr)
        {
            // std::cout << "Error with OpenDirectory results: "
            //  << std::string([[err localizedDescription] UTF8String])
            //  << std::endl;
            return;
        }

        for (ODRecord * re in od_results)
        {

            NSError* attrErr = nullptr;
            NSArray* userPolicyDataValues =
                [re valuesForAttribute:@"dsAttrTypeNative:accountPolicyData"
                    error:&attrErr];

            if (attrErr != nullptr || ![userPolicyDataValues count])
            {
                // std::cout << "No accountPolicyData found for UID: "
                // << uid.c_str() << std::endl;
                return;
            }

            NSData* plistData = userPolicyDataValues[0];
            NSPropertyListFormat format;
            NSError* plistError = nil;

            id plistDict = [NSPropertyListSerialization propertyListWithData:plistData
                                                        options:NSPropertyListMutableContainersAndLeaves
                                                        format:&format
                                                        error:&plistError];

            if (plistError != nil || ![plistDict isKindOfClass:[NSDictionary class]])
            {
                return;
            }

            NSDictionary* dict = (NSDictionary*)plistDict;
            nlohmann::json tree;

            for (NSString * key in dict)
            {
                id value = [dict objectForKey:key];
                std::string k = [key UTF8String];

                if ([value isKindOfClass:[NSNumber class]])
                {
                    tree[k] = [value doubleValue];
                }
                else if ([value isKindOfClass:[NSString class]])
                {
                    tree[k] = std::string([value UTF8String]);
                }
            }

            auto assign_safe = [&](const char* plistKey, const char* jsonKey, bool isInteger)
            {
                if (!tree.contains(plistKey)) return;

                const auto& val = tree[plistKey];

                try
                {
                    if (val.is_number())
                    {
                        if (isInteger)
                        {
                            policyData[jsonKey] = static_cast<int64_t>(val.get<double>());
                        }
                        else
                        {
                            policyData[jsonKey] = val.get<double>();
                        }
                    }
                    else if (val.is_string())
                    {
                        if (isInteger)
                        {
                            policyData[jsonKey] = std::stoll(val.get<std::string>());
                        }
                        else
                        {
                            policyData[jsonKey] = std::stod(val.get<std::string>());
                        }
                    }
                }
                catch (...)
                {
                    // Keep value in null if it fails
                }
            };

            // Assign values if present and valid
            assign_safe("creationTime", "creation_time", false);
            assign_safe("failedLoginCount", "failed_login_count", true);
            assign_safe("failedLoginTimestamp", "failed_login_timestamp", false);
            assign_safe("passwordLastSetTime", "password_last_set_time", false);
        }
    }

} // namespace od
