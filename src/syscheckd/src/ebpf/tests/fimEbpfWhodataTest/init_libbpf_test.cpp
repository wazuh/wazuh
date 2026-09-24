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
    MOCK_METHOD(void*, so__get_module_handle, (const char* so), (override));
    MOCK_METHOD(void*, getFunctionSymbol, (void* handle, const char* function_name), (override));
    MOCK_METHOD(int, freeLibrary, (void* handle), (override));
};


std::unique_ptr<MockDynamicLibraryWrapper> mock_sym_load;

libbpf_print_fn_t libbpf_print_cb = nullptr;
modules_log_level_t logged_level;
std::string logged_msg;

libbpf_print_fn_t mock_libbpf_set_print(libbpf_print_fn_t fn) {
    libbpf_print_cb = fn;
    return nullptr;
}

void call_libbpf_print(int level, const char* format, ...) {
    va_list args;
    va_start(args, format);
    libbpf_print_cb(level, format, args);
    va_end(args);
}

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

    EXPECT_CALL(*mock_sym_load, so__get_module_handle(::testing::_))
       .WillOnce(::testing::Return((void*)0x1000));
    EXPECT_CALL(*mock_sym_load, getFunctionSymbol(::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Return((void*)0x1001));
    EXPECT_CALL(*mock_sym_load, getFunctionSymbol(::testing::_, ::testing::StrEq("libbpf_set_print")))
        .WillOnce(::testing::Return((void*)mock_libbpf_set_print));

    int result = init_libbpf(std::move(mock_sym_load));

    ASSERT_EQ(result, 0);
}

TEST_F(InitLibbpfTest, LibbpfPrintForwardedToLog) {
    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::mock_loggingFunction = [](modules_log_level_t level, const char* msg) {
        logged_level = level;
        logged_msg = msg;
    };
    MockFimebpf::SetMockFunctions();

    EXPECT_CALL(*mock_sym_load, so__get_module_handle(::testing::_))
       .WillOnce(::testing::Return((void*)0x1000));
    EXPECT_CALL(*mock_sym_load, getFunctionSymbol(::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Return((void*)0x1001));
    EXPECT_CALL(*mock_sym_load, getFunctionSymbol(::testing::_, ::testing::StrEq("libbpf_set_print")))
        .WillOnce(::testing::Return((void*)mock_libbpf_set_print));

    ASSERT_EQ(init_libbpf(std::move(mock_sym_load)), 0);
    ASSERT_NE(libbpf_print_cb, nullptr);

    call_libbpf_print(0, "libbpf: failed to find valid kernel BTF: %d\n", -3);
    EXPECT_EQ(logged_level, LOG_DEBUG);
    EXPECT_EQ(logged_msg, "libbpf: failed to find valid kernel BTF: -3");

    call_libbpf_print(2, "libbpf: loading %s\n", "modern.bpf.o");
    EXPECT_EQ(logged_level, LOG_DEBUG_VERBOSE);
    EXPECT_EQ(logged_msg, "libbpf: loading modern.bpf.o");

    const std::string verifier_log = std::string(10000, 'x') + "The sequence of 8193 jumps is too complex.\n";
    call_libbpf_print(0, "%s", verifier_log.c_str());
    EXPECT_EQ(logged_msg.size(), 4096u);
    EXPECT_EQ(logged_msg.substr(logged_msg.size() - 42), "The sequence of 8193 jumps is too complex.");
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

    EXPECT_CALL(*mock_sym_load, so__get_module_handle(::testing::_))
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
