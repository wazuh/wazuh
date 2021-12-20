#include "sysInfoPackageLinuxParserRPM_test.hpp"
#include "packages/packageLinuxDataRetriever.h"
#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>


using ::testing::_;
using ::testing::Return;

class UtilsMock
{
    public:
        MOCK_METHOD(std::string, exec,(const std::string&, const size_t));
        MOCK_METHOD(bool, existsRegular,(const std::string& path));
};

static UtilsMock * m_mock = NULL;

std::string UtilsWrapper::exec(const std::string& cmd, const size_t bufferSize)
{
    return m_mock->exec(cmd,bufferSize);
}
bool UtilsWrapper::existsRegular(const std::string& path)
{
    return m_mock->existsRegular(path);
}

int rpmReadConfigFiles(const char * file, const char * target) { return 0; }
void rpmFreeRpmrc() { }
rpmtd rpmtdNew() { return 0; }
rpmtd rpmtdFree(rpmtd td) { return 0; }
rpmts rpmtsCreate() { return 0; }
int rpmtsOpenDB(rpmts ts, int dbmode) { return 0; }
int rpmtsCloseDB(rpmts ts) { return 0; }
rpmts rpmtsFree(rpmts ts) { return 0; }
int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags) { return 0; }
const char *rpmtdGetString(rpmtd td) { return 0; }
uint64_t rpmtdGetNumber(rpmtd td) { return 0; }
int rpmtsRun(rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet) { return 0; }
rpmdbMatchIterator rpmtsInitIterator(const rpmts ts, rpmDbiTagVal rpmtag, const void *keypointer, size_t keylen) { return 0; }
Header rpmdbNextIterator(rpmdbMatchIterator mi) { return 0; }
rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi) { return 0; }


class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (nlohmann::json&), ());
};

TEST(SysInfoPackageLinuxParserRPM_test, rpmFallbackFromLibRPM)
{
    CallbackMock wrapper;

    auto expectedPackage1 = R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm"})"_json;
    auto expectedPackage2 = R"({"name":"11","architecture":"12","description":"13","size":14,"version":"15:17-16","vendor":"18","install_time":"19","groups":"20","format":"rpm"})"_json;

    auto mock { std::make_unique<UtilsMock>() };
    m_mock = mock.get();
    EXPECT_CALL(*mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*mock, exec(_,_)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n11\t12\t13\t14\t15\t16\t17\t18\t19\t20\t\n"));
    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedPackage2)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data) {
            wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, rpmFallbackFromBerkleyDB)
{
    CallbackMock wrapper;

    auto expectedPackage1 = R"({"name":"1","architecture":"2","description":"3","size":4,"version":"5:7-6","vendor":"8","install_time":"9","groups":"10","format":"rpm"})"_json;
    auto expectedPackage2 = R"({"name":"11","architecture":"12","description":"13","size":14,"version":"15:17-16","vendor":"18","install_time":"19","groups":"20","format":"rpm"})"_json;

    auto mock { std::make_unique<UtilsMock>() };
    m_mock = mock.get();
    EXPECT_CALL(*mock, existsRegular(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*mock, exec(_,_)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n11\t12\t13\t14\t15\t16\t17\t18\t19\t20\t\n"));
    EXPECT_CALL(wrapper, callbackMock(expectedPackage1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedPackage2)).Times(1);

    getRpmInfo([&wrapper](nlohmann::json & data) {
            wrapper.callbackMock(data);
    });

}

TEST(SysInfoPackageLinuxParserRPM_test, emptyRpmFallback)
{
    CallbackMock wrapper;
    auto mock { std::make_unique<UtilsMock>() };
    m_mock = mock.get();
    EXPECT_CALL(*mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*mock, exec(_,_)).Times(1).WillOnce(Return(""));
    EXPECT_CALL(wrapper, callbackMock(_)).Times(0);

    getRpmInfo([&wrapper](nlohmann::json & data) {
            wrapper.callbackMock(data);
    });
}


TEST(SysInfoPackageLinuxParserRPM_test, invalidPackageParsingRpmFallback)
{
    CallbackMock wrapper;
    auto mock { std::make_unique<UtilsMock>() };
    m_mock = mock.get();
    EXPECT_CALL(*mock, existsRegular(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*mock, exec(_,_)).Times(1).WillOnce(Return("this is not a valid rpm -qa output"));
    EXPECT_CALL(wrapper, callbackMock(_)).Times(0);

    getRpmInfo([&wrapper](nlohmann::json & data) {
            wrapper.callbackMock(data);
    });
}