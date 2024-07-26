#include <benchmark/benchmark.h>

#include <map>
#include <random>
#include <string>
#include <vector>
#include <iostream>

#include <rapidjson/document.h>

#define MAX_SIZE 1000000

struct InputTest
{
    std::map<std::string, std::string> obj_data;
    std::vector<std::string> arr_data;

    explicit InputTest(size_t N)
        : obj_data()
        , arr_data()
    {
        auto digits = std::to_string(N).size();
        for (auto i = 0; i < N; ++i)
        {
            auto str = std::to_string(i);
            auto key = std::string(digits - str.size(), '0') + str;
            obj_data.emplace(key, key);
            arr_data.push_back(key);
        }
        auto b = false;
    }

    auto getInputObj(size_t size) const
    {
        auto i = 0;
        std::map<std::string, std::string> ret_data;
        for (auto it = obj_data.begin(); it != obj_data.end() && i < size; ++it, ++i)
          ret_data.emplace(it->first, it->second);

        return ret_data;
    }

    auto getInputArr(size_t size) const
    {
        auto i = 0;
        std::vector<std::string> ret_data(size);
        for (auto it = arr_data.begin(); it != arr_data.end() && i < size; ++it, ++i) ret_data.push_back(*it);

        return ret_data;
    }

    auto getKeyToSearch(size_t size) const { return arr_data[size / 2]; }
};

InputTest input_test(MAX_SIZE);

static void BM_RapidJsonSearchArrHits(benchmark::State& state)
{
    auto input = input_test.getInputArr(state.range(0));
    rapidjson::Document doc;
    doc.SetArray();

    for (auto& str : input)
    {
        rapidjson::Value val;
        val.SetString(str.c_str(), str.size(), doc.GetAllocator());
        doc.PushBack(val, doc.GetAllocator());
    }

    auto key = input_test.getKeyToSearch(state.range(0));

    for (auto _ : state)
    {
        decltype(doc.Begin()) itr;
        for (itr = doc.Begin(); itr != doc.End(); ++itr)
        {
            if (itr->IsString() && itr->GetString() == key)
            {
                break;
            }
        }

        if (itr == doc.End())
        {
            state.SkipWithError("Not found");
        }
    }
}
BENCHMARK(BM_RapidJsonSearchArrHits)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_RapidJsonSearchArrMiss(benchmark::State& state)
{
    auto input = input_test.getInputArr(state.range(0));
    rapidjson::Document doc;
    doc.SetArray();

    for (auto& str : input)
    {
        rapidjson::Value val;
        val.SetString(str.c_str(), str.size(), doc.GetAllocator());
        doc.PushBack(val, doc.GetAllocator());
    }

    auto key = std::string(std::string("0") + std::to_string(state.range()));

    for (auto _ : state)
    {
        decltype(doc.Begin()) itr;
        for (itr = doc.Begin(); itr != doc.End(); ++itr)
        {
            if (itr->IsString() && itr->GetString() == key)
            {
                break;
            }
        }

        if (itr != doc.End())
        {
            state.SkipWithError("Found");
        }
    }
}
BENCHMARK(BM_RapidJsonSearchArrMiss)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_RapidJsonSearchObjHit(benchmark::State& state)
{
    auto input = input_test.getInputObj(state.range(0));
    rapidjson::Document doc;
    doc.SetObject();

    for (auto& str : input)
    {
        rapidjson::Value val;
        val.SetString(str.first.c_str(), str.first.size(), doc.GetAllocator());
        doc.AddMember(val, val, doc.GetAllocator());
    }

    auto key = input_test.getKeyToSearch(state.range(0)).c_str();
    auto jKey = rapidjson::Value(key, doc.GetAllocator());

    for (auto _ : state)
    {
        if (!doc.HasMember(jKey))
        {
            state.SkipWithError("Not found");
        }
    }
}
BENCHMARK(BM_RapidJsonSearchObjHit)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_RapidJsonSearchObjMiss(benchmark::State& state)
{
    auto input = input_test.getInputObj(state.range(0));
    rapidjson::Document doc;
    doc.SetObject();

    for (auto& str : input)
    {
        rapidjson::Value val;
        val.SetString(str.first.c_str(), str.first.size(), doc.GetAllocator());
        doc.AddMember(val, val, doc.GetAllocator());
    }

    auto key = std::string(std::string("0") + std::to_string(state.range()));

    for (auto _ : state)
    {
        auto itr = doc.FindMember(key.c_str());
        if (itr != doc.MemberEnd())
        {
            state.SkipWithError("Found");
        }
    }
}
BENCHMARK(BM_RapidJsonSearchObjMiss)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_ArrHit(benchmark::State& state)
{
    auto input = input_test.getInputArr(state.range(0));
    auto key = input_test.getKeyToSearch(state.range(0));

    for (auto _ : state)
    {
        auto it = std::find(input.begin(), input.end(), key);
        if (it == input.end())
        {
            state.SkipWithError("Not found");
        }
    }
}
BENCHMARK(BM_ArrHit)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_ArrMiss(benchmark::State& state)
{
    auto input = input_test.getInputArr(state.range(0));
    auto key = std::string(std::string("0") + std::to_string(state.range()));

    for (auto _ : state)
    {
        auto it = std::find(input.begin(), input.end(), key);
        if (it != input.end())
        {
            state.SkipWithError("Found");
        }
    }
}
BENCHMARK(BM_ArrMiss)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_MapHit(benchmark::State& state)
{
    auto input = input_test.getInputObj(state.range(0));
    auto key = input_test.getKeyToSearch(state.range(0));

    for (auto _ : state)
    {
        auto it = input.find(key);
        if (it == input.end())
        {
            state.SkipWithError("Not found");
        }
    }
}
BENCHMARK(BM_MapHit)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);

static void BM_MapMiss(benchmark::State& state)
{
    auto input = input_test.getInputObj(state.range(0));
    auto key = std::string(std::string("0") + std::to_string(state.range()));

    for (auto _ : state)
    {
        auto it = input.find(key);
        if (it != input.end())
        {
            state.SkipWithError("Found");
        }
    }
}
BENCHMARK(BM_MapMiss)->RangeMultiplier(10)->Range(1, MAX_SIZE)->Unit(benchmark::kNanosecond);
