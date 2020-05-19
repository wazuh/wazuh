#include "dbsync_implementation.h"
#include <iostream>

uint64_t DBSyncImplementation::Initialize(
  const HostType host_type, 
  const DatabaseType db_type, 
  const std::string& path, 
  const std::string& sql_statement) {

  auto ret_val { 0ull };
  std::lock_guard<std::mutex> lock(m_mutex);
  try {
    auto db = FactoryDatabase::Create(db_type, path, sql_statement);
   
    m_dbsync_list.push_back(std::make_unique<DatabaseContext>(
      db,
      host_type,
      db_type
    ));

    ret_val = m_dbsync_list.back()->GetHandler();
    
  } catch (const std::exception e) {
    std::cout << e.what() << std::endl;
  }
  return ret_val;
}

bool DBSyncImplementation::Release() {
  auto ret_val { true };
  std::lock_guard<std::mutex> lock(m_mutex);
  m_dbsync_list.clear();
  return ret_val;
}

bool DBSyncImplementation::InsertBulkData(uint64_t handle, const char* json_raw) {
  auto ret_val { false };   
  std::lock_guard<std::mutex> lock(m_mutex); 
  try {
    auto json { nlohmann::json::parse(json_raw)};
    auto it = GetDatabaseContext(handle);
    if (m_dbsync_list.end() != it) {
      ret_val = (*it)->GetDatabase()->BulkInsert(json[0]);
    }
  } catch (const nlohmann::json::parse_error& e) {
    std::cout << "message: " << e.what() << std::endl
              << "exception id: " << e.id << std::endl
              << "byte position of error: " << e.byte << std::endl;
  } catch (const nlohmann::json::type_error& e) {
    std::cout << "message: " << e.what() << std::endl
              << "exception id: " << e.id << std::endl
              << "byte position of error: " << e.create << std::endl;
  }
  return ret_val;
}

std::vector<std::unique_ptr<DatabaseContext>>::iterator DBSyncImplementation::GetDatabaseContext(const uint64_t handler) {
  return std::find_if(m_dbsync_list.begin(),
                      m_dbsync_list.end(),
                      [handler](const std::unique_ptr<DatabaseContext>& handler_param) {
                        return handler_param->GetHandler() == handler;
                      });
}
