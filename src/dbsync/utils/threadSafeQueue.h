#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H
#include <queue>
#include <mutex>
#include <memory>
#include <atomic>
#include <condition_variable>

namespace Utils
{

	template<typename T>
	class SafeQueue
	{
	public:
		SafeQueue()
		: m_canceled{ false }
		{}
		SafeQueue& operator=(const SafeQueue&) = delete;
		SafeQueue(SafeQueue& other)
		: SafeQueue{}
		{
			Lock lock{ other.m_mutex };
			m_queue = other.m_queue;
		}
		~SafeQueue()
		{
			cancel();
		}

		void push(const T& value)
		{
			if (!m_canceled)
			{
				Lock lock{ m_mutex };
				m_queue.push(value);
				m_cv.notify_one();
			}
		}

		bool pop(T& value, const bool wait = true)
		{
			Lock lock{ m_mutex };
			if (wait)
			{
				m_cv.wait(lock, [this](){return !m_queue.empty() || m_canceled;});
			}
			const bool ret {!m_canceled && !m_queue.empty()};
			if (ret)
			{
				value = m_queue.front();
				m_queue.pop();
			}
			return ret;
		}

		std::shared_ptr<T> pop(const bool wait = true)
		{
			Lock lock{ m_mutex };
			if (wait)
			{
				m_cv.wait(lock, [this](){return !m_queue.empty() || m_canceled;});
			}
			const bool ret {!m_canceled && !m_queue.empty()};
			if (ret)
			{
				auto spData{ std::make_shared<T>(m_queue.front()) };
				m_queue.pop();
				return spData;
			}
			return nullptr;
		}

		bool empty() const
		{
			Lock lock{ m_mutex };
			return m_queue.empty();
		}

		size_t size() const
		{
			Lock lock{ m_mutex };
			return m_queue.size();
		}

		void cancel()
		{
			m_canceled = true;
			m_cv.notify_all();
		}

		bool cancelled() const
		{
			return m_canceled;
		}
	private:
		using Lock = std::unique_lock<std::mutex>;
		mutable std::mutex m_mutex;
		std::condition_variable m_cv;
		std::atomic_bool m_canceled;
		std::queue<T> m_queue;
	};
}//namespace Utils

#endif //THREAD_SAFE_QUEUE_H
