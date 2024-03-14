/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <Foundation/Foundation.h>
#include <CoreServices/CoreServices.h>

#include <string>
#include <deque>

void getAppsPathsFromLaunchServices(std::deque<std::string>& apps)
{
  CFBundleRef bundleRef = CFBundleGetBundleWithIdentifier(CFSTR("com.apple.LaunchServices"));
  if (bundleRef == nullptr)
  {
    throw std::runtime_error("LaunchServices bundle not found");
  }

  auto pFunc = (OSStatus(*)(CFArrayRef*)) CFBundleGetFunctionPointerForName(bundleRef, CFSTR("_LSCopyAllApplicationURLs"));
  if (pFunc == nullptr)
  {
    throw std::runtime_error("_LSCopyAllApplicationURLs function not found");
  }

  CFArrayRef appsList = nullptr;
  if (pFunc(&appsList) != noErr || appsList == nullptr)
  {
    throw std::runtime_error("Could not list LaunchServices applications");
  }

  for (id app in (__bridge NSArray *)appsList)
  {
    if (app != nil && [app isKindOfClass:[NSURL class]])
    {
      apps.push_back(std::string([[app path] UTF8String]));
    }
  }

  CFRelease(appsList);
}
