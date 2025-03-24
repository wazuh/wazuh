#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include "dynamic_library_wrapper.h"
#include "ebpf_mock_utils.hpp"


// Function under test
void close_libbpf(std::unique_ptr<DynamicLibraryWrapper> sym_load);


class MockDynamicLibraryWrapper : public DynamicLibraryWrapper {
public:
    MOCK_METHOD(void*, getModuleHandle, (const char* so), (override));
    MOCK_METHOD(void*, getFunctionSymbol, (void* handle, const char* function_name), (override));
    MOCK_METHOD(int, freeLibrary, (void* handle), (override));
};

std::unique_ptr<MockDynamicLibraryWrapper> mock_sym_load;


class CloseLibbpfTest : public ::testing::Test {
protected:
    void SetUp() override {
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
        mock_sym_load = std::make_unique<MockDynamicLibraryWrapper>();
    }

    void TearDown() override {
        bpf_helpers.reset();
    }
};


TEST_F(CloseLibbpfTest, ModuleExists) {
    bpf_helpers->module = reinterpret_cast<void*>(0x1234);

    EXPECT_CALL(*mock_sym_load, freeLibrary(bpf_helpers->module)).Times(1);
    close_libbpf(std::move(mock_sym_load));
    EXPECT_EQ(bpf_helpers, nullptr);
}

TEST_F(CloseLibbpfTest, ModuleNull) {

    bpf_helpers->module = nullptr;
    close_libbpf(std::move(mock_sym_load));
    EXPECT_EQ(bpf_helpers, nullptr);
}

TEST_F(CloseLibbpfTest, HelpersNull) {
    bpf_helpers.reset();
    EXPECT_CALL(*mock_sym_load, freeLibrary(::testing::_)).Times(0);
    close_libbpf(std::move(mock_sym_load));
    EXPECT_EQ(bpf_helpers, nullptr); 
}


void SetUpModule() {}
void TearDownModule() {}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    SetUpModule();
    int result = RUN_ALL_TESTS();
    TearDownModule();
    return result;
}
