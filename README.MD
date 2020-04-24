# PIXL PACK
> a small file wrapper to archive many assets into one streamable file

## Ok but wth is this ?
Well in theory it is pretty simple, take a file take another file glue them together add a bit of header and there you have it, a pixl-pack.

the format looks a bit like this
```
header {
    uint16 number of entries
    uint64 size of first entry
    entries {
        uint64 size of this entry
        uint64 offset to start of file after header
    }...
}
file_entry {
    null_terminated_string descriptor (max 256 chars)
    contents
}...
```
Actually it looks exactly like this! This is the entire pack format!

the functionality of this can be included in a single (arguabley quite large header)
for both c and c++ (im sure the ffi folks out there can make it work with other things if wanted)

## What would I use this for ?
Pixl pack is intended for games that have many assets, but usually don't want to ship them all individually. I am aware that other solutions such as tar, squashfs, cpio and such exist, but honestly, they offer way to much features for what you need for a game.

Please note that this is intended to serve more as a virtual readonly file-system then an archival solution. Also this does not compress data! I recommend mixing it with xz_utils to create packed archives.

## Usage
```cpp

    #include <pixl_pack.h>

    //in c++

    //reading
    std::vector<uint8_t> data_you_got_from_somewhere = somewhere();

    using namespace pixl::util;
    PackReader reader(data_you_got_from_somewhere);

    auto data = reader.filter("my_cool_stuff");

    std::cout << "some data with the name: "<< data.path() << std::endl;;

    for(uint8_t : data.get())
    {
        std::cout << "got some bytes! " << data <<std::endl;
    }

    //writing ( even simpler :) )
    using namespace pixl::util;

    std::vector<uint8_t> some_data_you_want_to_store;

    PackWriter writer;

    writer.insert(some_data_you_want_to_store,"location");

    auto archive_data = writer.generate();

```
```c

    #include <pixl_pack.h>

    //in c

    //reading
    pixl_pack_read_context ctx = pixl_pack_gen_read_context(somedata,somedata_len);

    for(pixl_read_node* node = ctx.entries_begin;
        node != PIXL_NULL;
        node = node->next)
        {
            if(strcmp(  pixl_entry_get_path(&node->entry,somedata,somedata_len),
                        "my_cool_stuff") == 0)
            {
                printf("found my data!")
                uint8_t* data = pixl_entry_get_data(&node->entry,somedata,somedata_len);
                size_t   size = pixl_entry_get_len (&node->entry,somedata,somedata_len);
                fwrite(data,1, size, stdout);
                break;
            }
        }

    //writing (again simpler)
    pixl_pack_write_context ctx = pixl_pack_gen_write_context();

    pixl_write_entry(&ctx,my_data,my_data_len,"location");

    size_t size = pixl_write_context_required_size(&ctx);
    uint8_t* data = pixl_write_context_assemble(&ctx);

```

included sample project
```sh
    #unpacks an archive to disk (note this cannot make folders as of now, so unpacking fails with subdirectories)
	ppack (<unpack> <archive.pp>)

    #packs files into an archive
    ppack (<pack> <archive.pp> <file>... )

```


> (c) Raphael Baier 2020 see [LICENSE.MD](LICENSE.MD) for license
>
> Part of the Libpixlengine