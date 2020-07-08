#ifndef THREAD_DISPATCHER_H
#define THREAD_DISPATCHER_H
#include <vector>
#include <thread>
#include <atomic>
#include <future>
#include "threadSafeQueue.h"
namespace Utils
{
	// *
	//  * @brief Minimal Dispatcher interface
	//  * @details Handle dispatching of messages of type Type
	//  * to be processed by calling Functor.
	//  * 
	//  * @tparam Type Messages types.
	//  * @tparam Functor Entity that processes the messages.
	 
	// template <typename Type, typename Functor>
	// class DispatcherInterface
	// {
	// public:
	// 	/**
	// 	 * @brief Ctor
	// 	 * 
	// 	 * @param functor Callable entity.
	// 	 * @param int Maximun number of threads to be used by the dispatcher.
	// 	 */
	// 	DispatcherInterface(Functor functor, const unsigned int numberOfThreads);
	// 	*
	// 	 * @brief Pushes a message to be processed by the functor.
	// 	 * @details The implementation decides whether the processing is sync or async.
	// 	 * 
	// 	 * @param data Message value.
		 
	// 	void push(const Type& data);
	// 	/**
	// 	 * @brief Rundowns the pending messages until reaches 0.
	// 	 * @details It should be a blocking call.
	// 	 */		
	// 	void rundown();
	// 	/**
	// 	 * @brief Cancels the dispatching.
	// 	 */
	// 	void cancel();
	// };

	template
	<
	typename Type,
	typename Functor
	>
	class AsyncDispatcher
	{
	public:
		AsyncDispatcher(Functor functor, const unsigned int numberOfThreads = std::thread::hardware_concurrency())
		: m_functor{ functor }
		, m_rundown{ false }
		, m_numberOfThreads{ numberOfThreads }
		{
			m_threads.reserve(m_numberOfThreads);
			for (unsigned int i = 0; i < m_numberOfThreads; ++i)
			{
				m_threads.push_back(std::thread{ &AsyncDispatcher<Type, Functor>::dispatch, this });
			}
		}
		AsyncDispatcher& operator=(const AsyncDispatcher&) = delete;
		AsyncDispatcher(AsyncDispatcher& other) = delete;
		~AsyncDispatcher()
		{
			m_queue.cancel();
			for (auto& thread : m_threads)
			{
				thread.join();
			}
		}

		void push(const Type& value)
		{
			m_queue.push(value);
		}

		void rundown()
		{
			m_rundown = true;
			if (!m_queue.empty() && !m_queue.cancelled())
			{
				auto fut {m_rundownPromise.get_future()};
				fut.wait();
				m_rundownPromise = std::promise<void>{};
			}
		}
		void cancel()
		{
			m_queue.cancel();
		}

		bool cancelled() const
		{
			return m_queue.cancelled();
		}
		unsigned int numberOfThreads() const
		{
			return m_numberOfThreads;
		}
	    size_t size() const
	    {
	    	return m_queue.size();
	    }

	private:
		void dispatch()
		{
			Type data{};
			while(m_queue.pop(data))
			{
				m_functor(data);
				if (m_rundown && m_queue.empty())
				{
					m_rundown = false;	
					m_rundownPromise.set_value();
				}
			}
		}
		Functor m_functor;
		SafeQueue<Type> m_queue;
		std::vector<std::thread> m_threads;
		std::atomic_bool m_rundown;
		std::promise<void> m_rundownPromise;
		const unsigned int m_numberOfThreads;
	};

	template <typename Input, typename Functor>
	class SyncDispatcher
	{
	public:
	    SyncDispatcher(Functor functor, const unsigned int numberOfThreads = 0)
	    : m_functor{functor}
	    {
	    }
	    void push(const Input& data)
	    {
	        m_functor(data);
	    }
	    size_t size() const {return 0;}
	    void rundown(){}
	    void cancel(){}
	    ~SyncDispatcher() = default;
	private:
	    Functor m_functor;
	};
}//namespace Utils
#endif //THREAD_DISPATCHER_H