#pragma once
#include <memory>
#include <atomic>
#include "dbengine.h"
#include "typedef.h"

static std::atomic_ullong g_handler = { 0ull };

class DbEngineContext {
public:
  DbEngineContext(
    std::unique_ptr<DbEngine>& dbengine, 
    const HostType host_type, 
    const DbEngineType db_type) : 
    m_dbengine(std::move(dbengine)),
    m_host_type(host_type),
    m_dbengine_type(db_type),
    m_handler(++g_handler) {}

  const std::unique_ptr<DbEngine>& GetDbEngine() { return m_dbengine; }
  const HostType& GetHostType() { return m_host_type; }
  const DbEngineType& GetDbEngineType() { return m_dbengine_type; }
  const uint64_t& GetHandler() { return m_handler; }
private:
  std::unique_ptr<DbEngine> m_dbengine;
  HostType m_host_type;
  DbEngineType m_dbengine_type;
  uint64_t m_handler;
};