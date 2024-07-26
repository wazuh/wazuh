#ifndef _STORE_MOCK_DRIVER_HPP
#define _STORE_MOCK_DRIVER_HPP

#include <gmock/gmock.h>

#include <store/idriver.hpp>

namespace store::mocks
{

/******************************************************************************/
// Helper functions to mock method responses
/******************************************************************************/
inline base::OptError driverError()
{
    return base::Error {"Mocked driver error"};
}

inline base::OptError driverOk()
{
    return base::OptError {};
}

template<typename T>
inline base::RespOrError<T> driverReadError()
{
    return base::Error {"Mocked driver read error"};
}

template<typename... Names>
inline base::RespOrError<Col> driverReadColResp(Names&&... names)
{
    return Col {std::forward<Names>(names)...};
}

inline base::RespOrError<Col> driverReadColResp(const Col& col)
{
    return col;
}

inline base::RespOrError<Doc> driverReadDocResp(const Doc& doc)
{
    return doc;
}

/******************************************************************************/
// Mock class
/******************************************************************************/
class MockDriver : public store::IDriver
{
public:
    MOCK_METHOD((base::OptError), createDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::RespOrError<Doc>), readDoc, (const base::Name&), (const, override));
    MOCK_METHOD((base::OptError), updateDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), upsertDoc, (const base::Name&, const Doc&), (override));
    MOCK_METHOD((base::OptError), deleteDoc, (const base::Name&), (override));
    MOCK_METHOD((base::RespOrError<Col>), readCol, (const base::Name&), (const, override));
    MOCK_METHOD((base::RespOrError<Col>), readRoot, (), (const, override));
    MOCK_METHOD((base::OptError), deleteCol, (const base::Name&), (override));
    MOCK_METHOD((bool), exists, (const base::Name&), (const, override));
    MOCK_METHOD((bool), existsDoc, (const base::Name&), (const, override));
    MOCK_METHOD((bool), existsCol, (const base::Name&), (const, override));
};

} // namespace store::mocks

#endif // _STORE_MOCK_DRIVER_HPP
