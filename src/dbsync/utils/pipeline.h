#ifndef PIPELINE_H
#define PIPELINE_H
#include <vector>
#include <functional>

namespace Utils
{
	template<typename T>
	struct IPipelineReader
	{
		virtual ~IPipelineReader() = default;
		virtual void receive(const T& data) = 0;
	};

	template<typename T>
	class PipelineWriter
	{
	protected:
		void send(const T& data)
		{
			for (auto& reader : m_readers)
			{
				reader.get().receive(data);
			}
		}
	public:
		PipelineWriter() = default;
		virtual ~PipelineWriter() = default;
		void addReader(IPipelineReader<T>& reader)
		{
			m_readers.push_back(reader);
		}
	private:
		std::vector<std::reference_wrapper<IPipelineReader<T>>> m_readers;
	};

	template<typename T>
	void connect(PipelineWriter<T>& writer,
				 IPipelineReader<T>& reader)
	{
		writer.addReader(reader);
	}
}

#endif //PIPELINE_H