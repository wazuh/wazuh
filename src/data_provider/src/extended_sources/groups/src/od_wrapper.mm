#import <Foundation/Foundation.h>
#import <OpenDirectory/OpenDirectory.h>
#include "od_wrapper.hpp"

void genODEntries(const std::string& recordTypeStr,
                  const std::string* recordStr,
                  std::map<std::string, bool>& names) {
  @autoreleasepool {
    ODSession* session = [ODSession defaultSession];
    NSError* err = nil;
    ODNode* root = [ODNode nodeWithSession:session name:@"/Local/Default" error:&err];
    if (err != nullptr) {
      NSLog(@"Error with OpenDirectory node: %@", [err localizedDescription]);
      return;
    }

    NSString* recordType = [NSString stringWithUTF8String:recordTypeStr.c_str()];
    NSString* record = recordStr ? [NSString stringWithUTF8String:recordStr->c_str()] : nil;

    NSString* attribute = [recordType isEqualToString:(kODRecordTypeGroups)] ?
                            kODAttributeTypePrimaryGroupID :
                            kODAttributeTypeUniqueID;

    ODQuery* query = [ODQuery queryWithNode:root
                             forRecordTypes:recordType
                                  attribute:attribute
                                  matchType:kODMatchEqualTo
                                queryValues:record
                           returnAttributes:kODAttributeTypeAllTypes
                             maximumResults:0
                                      error:&err];
    if (err != nullptr) {
      NSLog(@"Error with OpenDirectory query: %@", [err localizedDescription]);
      return;
    }

    NSArray* od_results = [query resultsAllowingPartial:NO error:&err];
    if (err != nullptr) {
      NSLog(@"Error with OpenDirectory results: %@", [err localizedDescription]);
      return;
    }

    for (ODRecord* re in od_results) {
      bool isHidden = false;
      NSArray* isHiddenValue = [re valuesForAttribute:@"dsAttrTypeNative:IsHidden" error:&err];
      if ([isHiddenValue count] >= 1) {
        NSString* val = [isHiddenValue objectAtIndex:0];
        isHidden = [[val description] isEqualToString:@"1"];
      }
      names[[[re recordName] UTF8String]] = isHidden;
    }
  }
}
