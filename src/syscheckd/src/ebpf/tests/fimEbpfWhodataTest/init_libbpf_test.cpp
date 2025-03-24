#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "dynamic_library_wrapper.h"
#include "ebpf_mock_utils.hpp"


void resetGlobalState() {
    if (bpf_helpers) {
        bpf_helpers.reset();
    }
}

extern int init_libbpf(std::unique_ptr<DynamicLibraryWrapper> sym_load);

class MockDynamicLibraryWrapper : public DynamicLibraryWrapper {
public:
    MOCK_METHOD(void*, getModuleHandle, (const char* so), (override)); 
    MOCK_METHOD(void*, getFunctionSymbol, (void* handle, const char* function_name), (override)); 
    MOCK_METHOD(int, freeLibrary, (void* handle), (override)); 
};


std::unique_ptr<MockDynamicLibraryWrapper> mock_sym_load;

class InitLibbpfTest : public ::testing::Test {
protected:
    void SetUp() override {
        MockFimebpf::mock_loggingFunction = mock_loggingFunction;
        MockFimebpf::SetMockFunctions();
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
        mock_sym_load = std::make_unique<MockDynamicLibraryWrapper>();
    }
    void TearDown() override {
    }
};


TEST_F(InitLibbpfTest, InitLibbpfTestOK) {
    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::SetMockFunctions();

    EXPECT_CALL(*mock_sym_load, getModuleHandle(::testing::_))
       .WillOnce(::testing::Return((void*)0x1000));
    EXPECT_CALL(*mock_sym_load, getFunctionSymbol(::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Return((void*)0x1001)); 

    int result = init_libbpf(std::move(mock_sym_load));

    ASSERT_EQ(result, 0);
}

TEST_F(InitLibbpfTest, abspathFailure) {
    MockFimebpf::mock_abspath = nullptr;
    MockFimebpf::SetMockFunctions();

    int result = init_libbpf(std::move(mock_sym_load));

    ASSERT_EQ(result, 1);
}

TEST_F(InitLibbpfTest, InitLibbpfTestFailed) {
    MockFimebpf::mock_loggingFunction = mock_loggingFunction;
    MockFimebpf::mock_abspath = mock_abspath;

    MockFimebpf::SetMockFunctions();

    EXPECT_CALL(*mock_sym_load, getModuleHandle(::testing::_))
       .WillOnce(::testing::Return((void*)0x1000));
    EXPECT_CALL(*mock_sym_load, getFunctionSymbol(::testing::_, ::testing::_))
        .WillOnce(::testing::Return(nullptr))
        .WillRepeatedly(::testing::Return((void*)0x1001));
    EXPECT_CALL(*mock_sym_load, freeLibrary(::testing::_))
        .WillOnce(::testing::Return(0));

    int result = init_libbpf(std::move(mock_sym_load));

    ASSERT_EQ(result, 1);
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
