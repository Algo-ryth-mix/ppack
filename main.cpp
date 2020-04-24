#define _CRT_SECURE_NO_WARNINGS

#include "pixl_pack.h"
#include <cstdio>
#include <vector>
#include <iostream>



void print_usage_and_exit()
{
	std::cout << R"(
	Usage:
		ppack_test (<pack> <archive.pp> <file>... ) 
		ppack_test (<unpack> <archive.pp>)
	)";
	exit(1);
}

int main(int argc, char** argv)
{
	if (argc <= 2) print_usage_and_exit();

	if (strcmp(argv[1], "pack") == 0)
	{
		pixl::util::PackWriter writer;
		std::vector<std::vector<uint8_t>> datas;

		for (int i = 3; i < argc; ++i)
		{
			FILE* f = fopen(argv[i], "rb");
			fseek(f, 0, SEEK_END);
			auto size = ftell(f);

			datas.emplace_back();
			datas.back().resize(size, 0);

			fseek(f, 0, SEEK_SET);
			fread(datas.back().data(), 1, size, f);
			fclose(f);
			writer.insert(datas.back(), argv[i]);
		}

		auto output = writer.generate();
		FILE* f = fopen(argv[2], "wb");
		fwrite(output.begin(), 1, output.size(), f);
		fclose(f);

	}
	else if (strcmp(argv[1], "unpack") == 0)
	{
		std::vector<uint8_t> data;
		FILE* f = fopen(argv[2], "rb");
		fseek(f, 0, SEEK_END);
		auto size = ftell(f);


		data.resize(size, 0);

		fseek(f, 0, SEEK_SET);
		fread(data.data(), 1, size, f);
		fclose(f);

		pixl::util::PackReader reader(data);

		for(auto& prx : reader)
		{
			FILE* writer = fopen(prx.path().c_str(), "wb");
			fwrite(prx.get().begin(), 1, prx.get().size(), writer);
			fclose(writer);
		}
	}
	else print_usage_and_exit();


}
