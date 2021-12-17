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
    std::cout << "exec: " << cmd << std::endl;
    return m_mock->exec(cmd,bufferSize);
}
bool UtilsWrapper::existsRegular(const std::string& path)
{
    std::cout << "existsRegular: " << path << std::endl;
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

TEST(SysInfoPackageLinuxParserRPM_test, getPackages)
{
    auto mock { std::make_unique<UtilsMock>() };
    m_mock = mock.get();
    EXPECT_CALL(*mock, exec(_,_)).Times(1).WillOnce(Return("1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t\n"));
    EXPECT_CALL(*mock, existsRegular(_)).Times(1).WillOnce(Return(false));

    getRpmInfo([] (nlohmann::json & json) {
        std::cout << json.dump(4) << std::endl;
    });
}
