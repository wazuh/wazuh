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

} // namespace od
