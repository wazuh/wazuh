#pragma once

#include <iyaml_document.hpp>

#include <gmock/gmock.h>

class MockYamlDocument : public IYamlDocument
{
public:
    MOCK_METHOD(YamlNode, GetRoot, (), (override));
    MOCK_METHOD(bool, IsValidDocument, (), (const, override));
};
