#ifndef PIXL__INCLUDE_PIXL_PACK_H__
#define PIXL__INCLUDE_PIXL_PACK_H__
/*
 * Copyright 2020 Raphael Baier
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

//TODO(algo-ryth-mix)/archive-generation/ somewhere we add a spurious \n 
//TODO(cont.) in some files at the end,I have no idea where it comes from,
//TODO(cont.) but it needs to go. It was not invited!

/**@file pixl_pack.h
 * @brief implements a small and easy to use archive solution, without compression
 * the idea is to use a compression library after packing to generate one compressed
 * data structure (e.g.: archive.pp.xz), uses an aproach where the data is visible
 * directly in the compressed archive, for easy debugging and, possibly streaming data
 * was made for the lib-pixl-engine
 * (optional) submodules of the lpe used:
 * - array-view
 */


#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <climits>
#include <string>
#include <utility>
#include <vector>
#include <stdexcept>
#include <list>
#include <algorithm>


#define PIXL_INTERNAL_ALLOC(T) new (T)
#define PIXL_INTERNAL_ALLOC_ARRAY(T,SIZE) new T[(SIZE)]
#define PIXL_INTERNAL_FREE(PTR) delete (PTR)
#define PIXL_INTERNAL_FREE_ARRAY(PTR) delete[] (PTR)

//these will not be undefined in case the programmer
//is not sure wether his environment will compile with or
//without __cplusplus defined
#define PIXL_PACK_COMPAT_FREE delete
#define PIXL_PACK_COMPAT_FREE_ARRAY delete[] 

#define PIXL_NULL nullptr
#define PIXL_PTR_CAST(TO) reinterpret_cast<TO>
#define PIXL_CAST(TO) static_cast<TO>
#define PIXL_CONST const
#define PIXL_MUTABLE mutable
namespace pixl {
namespace util {

#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#define PIXL_INTERNAL_ALLOC(T) ((T)*) malloc(sizeof((T)))
#define PIXL_INTERNAL_ALLOC_ARRAY(T,SIZE) ((T)*) malloc(sizeof((T)) * SIZE)
#define PIXL_INTERNAL_FREE(PTR) free((PTR));
#define PIXL_INTERNAL_FREE_ARRAY(PTR) free((PTR));

#define PIXL_PACK_COMPAT_FREE free
#define PIXL_PACK_COMPAT_FREE_ARRAY free 

#define PIXL_NULL NULL
#define PIXL_PTR_CAST(TO) (TO)
#define PIXL_CAST(TO) (TO)
#define PIXL_CONST
#define PIXL_MUTABLE 
#endif

#define NUM_ENTRIES_SIZE 2
#define ENTRY_MAX_PATH_LEN 255

#define BIT_MASK(__TYPE__, __ONE_COUNT__) \
    ((__TYPE__) (-((__ONE_COUNT__) != 0))) \
    & (((__TYPE__) -1) >> ((sizeof(__TYPE__) * CHAR_BIT) - (__ONE_COUNT__)))


typedef struct pixl_file_entry{
    uint_fast64_t offset;
    uint_fast64_t size;
    PIXL_MUTABLE uint_fast16_t path_size;
} pixl_file_entry;

typedef struct pixl_read_node
{
    pixl_read_node * prev;
    pixl_read_node * next;
    pixl_file_entry entry;
} pixl_read_node;

typedef struct pixl_pack_read_context {
    uint_fast16_t entries;
    pixl_read_node * entries_begin;
    pixl_read_node * entries_end;
    size_t read_offset;
} pixl_pack_read_context;

typedef union pixl_destructured_uint16 {
    uint16_t value;
    uint8_t bits[2];
} pixl_destructured_uint16;

typedef union pixl_destructured_uint64 {
    uint64_t value;
    uint8_t bits[8];
} pixl_destructured_uint64;

typedef struct pixl_write_node {
    PIXL_CONST uint8_t* data;
    size_t len;
    const char * name;
    pixl_write_node* next;
} pixl_write_node;


typedef struct pixl_pack_write_context {
    pixl_write_node* start;
    pixl_write_node* cursor;
    uint16_t num_entries;
} pixl_pack_write_context;


/** 
 * @brief copy and advance inner
 * @detail copies from src + offset into dest, size amount of bytes and adds size to offset when done
 * @param [in,out] dest the destination for your data
 * @param [in] src the source of your data
 * @param [in,out] offset the offset in the source array
 * @param [in] size the amount of bytes to copy / advance
 * 
 */
inline void pixl_caai(void* dest,
                     const uint8_t* src,
                     size_t* offset,
                     size_t size)
{
    memcpy(dest,src+(*offset),size);
    (*offset)+=size;
}
/** 
 * @brief copy and advance outer
 * @detail copies from src offset into dest + offset, size amount of bytes and adds size to offset when done
 * @param [in,out] dest the destination for your data
 * @param [in] src the source of your data
 * @param [in,out] offset the offset in the destination array
 * @param [in] size the amount of bytes to copy / advance
 * 
 */
inline void pixl_caao(uint8_t* dest,
                     const void* src,
                     size_t* offset,
                     size_t size)
{
    memcpy(dest+(*offset),src,size);
    (*offset)+=size;
}

/** 
 * @brief checks if it is safe to read further into the array
 * @param [in] size the size of the data
 * @param [in] offset the cursor into the data
 * @param [in] want_to_read the amount of bytes you want to read from the current cursor position
 * @returns true if it is safe to read, otherwise false
 * 
 */
inline bool pixl_peak_data(size_t size,size_t offset,size_t want_to_read)
{
    return offset + want_to_read <= size;
}

/** 
 * @brief returns the min between two size_t's
 */
inline size_t pixl_sizet_min(size_t a, size_t b)
{
    return a < b ? a : b;
}

/**@brief generates a context for reading a pixl_pack
 * @param [in] data the pointer to the data you want to interpret as a pixl_pack
 * @param [in] size the size of the data you want to interpret as a pixl_pack
 *
 * @returns pixl_pack_read_context a context for extracting data from the archive
 * @see pixl_entry_get_data()
 * @post pixl_pack_free_read_context()
 * 
 */
inline pixl_pack_read_context pixl_pack_gen_read_context(PIXL_CONST uint8_t* data, size_t size)
{

    //create header
    pixl_pack_read_context header{0,PIXL_NULL,PIXL_NULL,0};

    //check if there is enough data, to begin reading
    if(size < NUM_ENTRIES_SIZE ) return header;


    //get entries size
    uint16_t  entries;
    memset(&entries,0,sizeof uint16_t);
    pixl_caai(&entries,data,&header.read_offset,NUM_ENTRIES_SIZE);
    header.entries = entries;

    //get size of header in data
    const size_t header_info_size = sizeof uint16_t + sizeof uint64_t +
        ((entries- 1) * (sizeof uint64_t + sizeof uint64_t));


    pixl_read_node* last = PIXL_NULL;

    //read all entries
    for(size_t itr = 0; itr < header.entries; itr++)
    {
        pixl_read_node* node = PIXL_INTERNAL_ALLOC(pixl_read_node);
        node->entry.path_size = 0;


    	//read size
        if(pixl_peak_data(size,header.read_offset,sizeof uint64_t))
        {
            uint64_t sz = 0;
        	memset(&sz,0,sizeof uint64_t);
            pixl_caai(&sz,data,&header.read_offset,sizeof uint64_t);
            node->entry.size = sz;
        }
        else
        {
            //error while reading size, error out
            PIXL_INTERNAL_FREE(node);
        	if(last)
				last->next = PIXL_NULL;
            header.entries_end =last;
            header.entries = 0;
            return header;
        }

        //check if this is the first read
        if(header.entries_begin != PIXL_NULL)
        {
            //link entries
            node->prev = last;
            last->next = node;
            node->next = PIXL_NULL;
            header.entries_end = node;

            //read offset
            if(pixl_peak_data(size,header.read_offset,sizeof uint64_t))
            {
                pixl_destructured_uint64 offs;
                memset(offs.bits,0,sizeof uint64_t);
                pixl_caai(offs.bits,data,&header.read_offset,sizeof uint64_t);
                node->entry.offset = offs.value + header_info_size;
            }
            else
            {
                //error while reading offset, error out
                PIXL_INTERNAL_FREE(node);
                last->next = PIXL_NULL;
                header.entries_end =last;
                header.entries = 0;
                return header;
            }
        }
        else
        {
            //create first entry
            node->prev = PIXL_NULL;
            node->next = PIXL_NULL;
            node->entry.offset = header_info_size;
            header.entries_begin = node;
            header.entries_end = node;
            last = node;
        }


    }
	return header;
}


/**@brief frees a pixl_pack_read_context after you are done using it
 * @param context the read context to destroy
 */
inline void pixl_pack_free_read_context(pixl_pack_read_context* context)
{

    //No entries written, nothing to clean
    if(context->entries_begin == PIXL_NULL) return;
    //free all nodes
    for( pixl_read_node* node = context->entries_begin->next;
         node != PIXL_NULL;
         node = node->next){
             PIXL_INTERNAL_FREE(node->prev);
         }

    //free the remaining node (Note that in the case of only one node,
    //this will also clear the first node)
    PIXL_INTERNAL_FREE(context->entries_end);
}

/**@brief gets the length of the path of the passed entry
 * @param entry a pointer to the entry you want to inspect
 * @param data the pixl-pack data structure
 * @param size the size of the pixl-pack data structure
 * @returns the length of the associated path
 */
inline size_t pixl_entry_get_path_len(PIXL_CONST pixl_file_entry* entry,PIXL_CONST uint8_t* data, size_t size)
{
    if(entry->offset > size - ENTRY_MAX_PATH_LEN) return 0;

    size_t path_len;

    //get len of path
    if(entry->path_size != 0)
    {
        path_len = entry->path_size;
    } else {
        path_len = strnlen(PIXL_PTR_CAST(const char *)(data+entry->offset),ENTRY_MAX_PATH_LEN);
        entry->path_size = path_len;
    }
    return path_len;

}

/**@brief gets the associated path to the entry
 * @param entry a pointer to the entry you want to inspect
 * @param data the pixl-pack data structure
 * @param size the size of the pixl-pack data structure
 * @returns the path of the entry or "out of bounds" if the entry->offset field was invalid
 */
inline char * pixl_entry_get_path(PIXL_CONST pixl_file_entry* entry,PIXL_CONST uint8_t* data,size_t size)
{
    //check that we are within bounds
    if(entry->offset > size - ENTRY_MAX_PATH_LEN)
    {
        static const char oob_message[] = "out of bounds";
        char* ret = PIXL_INTERNAL_ALLOC_ARRAY(char,sizeof oob_message);
        memcpy(ret,oob_message,sizeof oob_message);
        return ret;
    }
    else
    {
        size_t path_len = pixl_entry_get_path_len(entry,data,size);

        //create string
        char * path = PIXL_INTERNAL_ALLOC_ARRAY(char,path_len+1);
        memcpy(path,data+entry->offset,path_len);
        path[path_len] = '\0';

        return path;
    }
}


/**@brief gets a data pointer to the associated entry
 * @param entry the entry you want to inspect
 * @param data the pixl-pack data structure
 * @param size the size of the pixl-pack data structure
 * @returns a pointer to the data
 * @see pixl_entry_get_len to check how long your data is
 */
inline PIXL_CONST uint8_t* pixl_entry_get_data(PIXL_CONST pixl_file_entry* entry,PIXL_CONST uint8_t* data,size_t size)
{
    //check that we are within bounds
    if(entry->offset + entry->size > size || entry->offset > size - ENTRY_MAX_PATH_LEN) return PIXL_NULL;
    else
    {
        //get len of path and return data ptr from there
        size_t path_len = pixl_entry_get_path_len(entry,data,size);
        return data + entry->offset + path_len+1;
    }
}

/**@brief gets the offset of your data within the original pack descriptor
 * @param entry the entry you want to inspect
 * @param data the pixl-pack data structure
 * @param size the size of the pixl-pack data structure
 * @return the offset of your data, your data is located at data + pixl_entry_get_offset(e,data,len)
 * @see pixl_entry_get_data to get the pointer directly
 */
inline size_t  pixl_entry_get_offset(PIXL_CONST pixl_file_entry* entry,PIXL_CONST uint8_t* data,size_t size)
{
    //check that we are within bounds
    if(entry->offset + entry->size > size || entry->offset > size - ENTRY_MAX_PATH_LEN) return 0;
    else
    {
        //get len of path and return data ptr from there
        size_t path_len = pixl_entry_get_path_len(entry,data,size);
        return  entry->offset + path_len +1;
    }
}

/**@brief gets the length of the data at the location of entry
 * @param entry the entry you want to get the length of
 * @param data the pixl-pack data structure
 * @param size the size of the pixl-pack data structure
 * @returns the length of the data entry
 * @see pixl_entry_get_data to get the data
 */
inline size_t pixl_entry_get_len(PIXL_CONST pixl_file_entry* entry,PIXL_CONST uint8_t* data,size_t size)
{
    //check that we are within bounds
    if(entry->offset + entry->size > size || entry->offset > size - ENTRY_MAX_PATH_LEN) return 0;
    else
    {
        //get len of path and deduct it from the entry-size
        size_t path_len = pixl_entry_get_path_len(entry,data,size);
        return entry->size - path_len;
    }
}


/**@brief creates a context for writing a pixl-pack
 */
inline pixl_pack_write_context pixl_pack_gen_write_context()
{
    PIXL_CONST pixl_pack_write_context context{PIXL_NULL,PIXL_NULL,0};
    return context;
}
/**@brief enques a single entry in the data section of the pixl-pack
 * @param [in,out] ctx the write context
 * @param [in] data the data you want to store in this section
 * @param [in] data_len the length of the data you want to store
 * @param [in] name the path or descriptor you want to store your data under
 * @pre pixl_pack_gen_write_context()
 */
inline void pixl_write_entry(pixl_pack_write_context* ctx ,PIXL_CONST uint8_t* data,size_t data_len, const char * name)
{
    //create new entry
    pixl_write_node* node = PIXL_INTERNAL_ALLOC(pixl_write_node);
    node->data = data;
    node->len = data_len;
    node->name = name;
	node->next = PIXL_NULL;

    //check if this is the first entry
    if(ctx->start == PIXL_NULL)
    {
        ctx->start = node;
        ctx->cursor = node;
    }
    else
    {
        ctx->cursor->next = node;
        ctx->cursor = node;
    }
    ctx->num_entries++;
}

/**@brief checks how much space is required to write this write-context to memory
 * @param [in,out] ctx the write context
 * @pre pixl_pack_gen_write_context()
 * @pre pixl_write_entry()
 */
inline size_t pixl_write_context_required_size(pixl_pack_write_context* ctx)
{
    //check if the context has any values
    if(ctx->start == PIXL_NULL || ctx->num_entries <= 0) return 0;

    const size_t header_size =  sizeof uint16_t + sizeof uint64_t + (ctx->num_entries - 1) * sizeof uint64_t * 2;

    size_t required_size = header_size;

    //iterate all nodes
    for(pixl_write_node* node = ctx->start;
        node != PIXL_NULL;
        node = node->next)
    {
        //get required size for path with max ENTRY_MAX_PATH_LEN
        size_t path_len = strnlen(node->name,ENTRY_MAX_PATH_LEN)+1;
        required_size += path_len;

        //get requires size for data with, int_with_bytes_sizeof uint64_t::max -
        //the path len, as maximum size
        required_size += pixl_sizet_min(node->len,BIT_MASK(size_t,sizeof uint64_t * CHAR_BIT)
                                                  - path_len);
    }
    return required_size;
}

/**@brief assembles the archive from the entries in the data-structure
 * @note the returned data will be pixl_write_context_requried_size() bytes long, you can use the archive directly
 * @note if your are using c++ the data can be freed with delete[] in c use free(), if you are unsure
 * @note what your compiler picked use PIXL_PACK_COMPAT_FREE_ARRAY()
 * @param [in,out] ctx the write context
 * @pre pixl_pack_gen_write_context()
 * @pre pixl_write_entry()
 */
inline uint8_t* pixl_write_context_assemble(pixl_pack_write_context* ctx)
{

    size_t size = pixl_write_context_required_size(ctx);

    if(size == 0) return PIXL_NULL;

    const size_t header_info_size = sizeof uint64_t + (ctx->num_entries - 1) * sizeof uint64_t * 2;

    //create array that is big enough for all data
    uint8_t* data = PIXL_INTERNAL_ALLOC_ARRAY(uint8_t, size);

    //cursor where we are in the data
    size_t offset = sizeof(uint16_t);
    memcpy(data,&ctx->num_entries,sizeof uint16_t);

    memset(data+offset,0,header_info_size);

    size_t data_offset = offset + header_info_size;

    size_t infileoffs = 0;

    for(pixl_write_node* node = ctx->start;
        node != PIXL_NULL;
        node = node->next)
    {
        //get required size for path with max ENTRY_MAX_PATH_LEN
        size_t path_len = strnlen(node->name,ENTRY_MAX_PATH_LEN)+1;
        //get requires size for data with, int_with_bytes_sizeof uint64_t::max -
        //the path len, as maximum size
        size_t data_len = pixl_sizet_min(node->len,BIT_MASK(size_t,sizeof uint64_t * CHAR_BIT)
                                                  - path_len);

    	size_t overall_len = path_len + data_len;

        //write to header
    	*(uint64_t*)(data+offset) = overall_len;
        //advance header position
    	// & write offset
    	if(node != ctx->start){
    		*(uint64_t*)(data+offset+sizeof uint64_t) = infileoffs;
			offset += sizeof uint64_t;

    	}
        //advance header by size only
	    offset+= sizeof uint64_t;

        //advance written position
		infileoffs += overall_len;

        //write & advance data
        pixl_caao(data,PIXL_PTR_CAST(const uint8_t*)(node->name),&data_offset,path_len);
        pixl_caao(data,node->data,&data_offset,data_len);

    }
	return data;
}

/**@brief frees the write context
 */
inline void pixl_write_context_free(pixl_pack_write_context* ctx)
{
	//check if there is something to free
    if(ctx->start == PIXL_NULL) return;

	pixl_write_node* to_assign;
	for(pixl_write_node* node = ctx->start;
        node != PIXL_NULL;
        node = to_assign)
    {
		//store the next one to clear
		to_assign = node->next;
		//clear current one
		PIXL_INTERNAL_FREE(node);
    }
}

#ifdef __cplusplus

#if !defined(PIXL_PACK_NO_CPP)
	
#ifndef PIXL_LIBRARY

/**@class view
 * @brief implementation if lpe array-view is not available
 * a reference-counting view into a raw array, implements most of the required things
 * for a standard stl container
 * @tparam T the value-type of the target_array
 */
template<class T>
class view
{
	
public:
    using value_type = T;
	using value_ptr = T*;
    using size_type = std::size_t;
    using iterator = T*;
	using const_iterator = const T*;

    view(const view& other) : reference_count(other.reference_count), target_array(other.target_array),offset(other.offset),target_size(other.target_size)
    {
   		++*this->reference_count;
    }
    view(view&& other) noexcept : reference_count(other.reference_count), target_array(other.target_array),offset(other.offset),target_size(other.target_size)
    {
		++*this->reference_count;
    }
    view& operator=(const view& other)
    {
    	if(this == &other)
            return *this;
    	
	    this->target_array = other.target_array;
    	this->offset = other.offset;
    	this->target_size = other.target_size;
    	this->reference_count = other.reference_count;
		++*this->reference_count;
    	return *this;
    }
    view& operator=(view&& other) noexcept  {
	    this->target_array = other.target_array;
    	this->offset = other.offset;
    	this->target_size = other.target_size;
    	this->reference_count = other.reference_count;
		++*this->reference_count;
        return *this;
    }

	view(value_ptr target,size_type view_size,size_type offset = 0,bool take_ownership = false)
        : reference_count(take_ownership ? new int(1):nullptr), target_array(target),offset(offset),target_size(view_size){}

	~view()
	{
		if( reference_count && --*reference_count == 0){ delete[] target_array;delete reference_count;}
	}

	/**@brief gets the value at index idx
	 *  checks if the index is valid before returning and throws and std::out_of_range exception if it is not
	 *  @param idx the index to query
	 *  @returns the value at idx
	 */
	value_type& at(size_type idx)
	{
		if(idx > target_size) throw std::out_of_range("view subscript out of range");
		return this->operator[](idx);
	}
	
	/**@brief gets the value at index idx
	 * @param idx the index to query
	 * @returns the value at idx
	 * @see at() for a guarded version
	 */	
	value_type& operator[](size_type idx)
	{
		return *(target_array + offset + idx);
	}
	
	/**@brief const version of above
	 * @see value_type& operator[](size_type)
	 */
	value_type operator[](size_type idx) const
	{
		return *(target_array + offset + idx);
	}
	iterator begin()
	{
		return target_array + offset;
	}

	auto data()
    {
	    return begin();
    }

	auto data() const
    {
	    return begin();
    }
	
	iterator end()
	{
		return begin() + target_size;
	}

	const_iterator begin() const
	{
		return target_array + offset;
	}

	const_iterator end() const
	{
		return begin() + target_size;
	}

	/**@brief gets the size of the target array-view
	 */
	size_type size() const noexcept
	{
		return target_size;
	}

	/**@brief gets the max size this container could grow to.
	 * since the container is non resizable same as size()
	 */
	size_type max_size() const noexcept
	{
		return target_size;
	}

private:
	mutable int* reference_count = nullptr;
	value_ptr target_array;
	size_type offset;
	size_type target_size;
};
#else
	template<class T>
	using view = array_view<T>;
	
#endif

/**@class PackReader
 * @brief a wrapper around pixl_pack_read_context
 * makes it trivial to read pixl-pack archives with c++
 */
class PackReader
{

public:

    /**@class proxy
     *  
     * @brief clumps up a path and a view into the target array
     * also adds some error-checking
     */
	class proxy
    {

	public:

		proxy() : internal_view(nullptr,0,0),has_value(false){}
        proxy(view<const uint8_t> view, std::string path) : internal_view(std::move(view)),internal_path(std::move(path)),has_value(true){}

		proxy(const proxy& other) = default;
        proxy(proxy&& other) noexcept = default;
        proxy& operator=(const proxy& other) = default;
        proxy& operator=(proxy&& other) noexcept = default;


		/**@brief gets the full-path or descriptor of the
		 * file you are looking at
		 * @returns std::string the fully-qualified descriptor of the entry
		 */
        std::string path() const
        {
	        return internal_path;
        }

		/**@brief checks if the entry is valid
		 * @returns true if it is, false otherwise
		 */
		bool valid() const noexcept
        {
	        return has_value;
        }

		/**@brief gets the data of the entry wrapped in an archive-view
		 */
    	view<const uint8_t>& get()
        {
	        return internal_view;
        }
		
		/**@brief gets the data of the entry wrapped in an archive-view in an immutable context
		 */
		const view<const uint8_t>& get() const
        {
	        return internal_view;
        }
        /**@see valid()
         */
		operator bool() const noexcept
        {
	        return valid();
        }
	private:		
        friend class PackReader;

		view<const uint8_t> internal_view;
		std::string internal_path;
		bool has_value;		
    };
	
    /**@brief constructor for PackReader, pass the raw array + size
     * @param data the data of the archive
     * @param size the length of the data
     */
	PackReader(const uint8_t* data,size_t size)
    {
	    open(data,size);
    }

	/**@brief constructor for PackReader, pass a byte-vector
     * @param pack_data
     */
    PackReader(const std::vector<uint8_t>& pack_data) : PackReader(pack_data.data(),pack_data.size()) {}

    /**@brief constructor for PackReader, pass a byte-view
     * @param pack_data
     */
    PackReader(const view<const uint8_t>& pack_data) : PackReader(pack_data.data(),pack_data.size()) {}

	~PackReader() { close(); }

	/**@brief closes the read context
	 * if this is called you must call open() before using the Reader again
	 */
    void close()
	{
		pixl_pack_free_read_context(&context);
	}

	/**@brief opens the archive and creates all the entries
	 * @param data the data of the archive
	 * @param size the length of the data of the archive
	 */
	void open(const uint8_t* data,size_t size)
	{
		if(this->data)
		{
			close();
		}
    	this->data = data;
    	this->size = size;
		context = pixl_pack_gen_read_context(data,size);
        struct proto_iterator
        {
	        proto_iterator(pixl_read_node* node) :node(node) {}

        	proto_iterator& operator++()
	        {
	        	node = node->next;
		        return *this;
	        }
        	pixl_read_node& operator*() const
            {
		        return *node;
	        }

        	bool operator!=(const proto_iterator& rhs) const
            {
		        return node != rhs.node;
	        }
        	
        	pixl_read_node* node;
        	
        };
		std::for_each(proto_iterator(context.entries_begin),proto_iterator(context.entries_end->next),[&](const pixl_read_node& node)
		{
			auto* entry = &node.entry;
			const std::string path = pixl_entry_get_path(entry,data,size);
            const std::size_t entry_offset = pixl_entry_get_offset(entry,data,size);
			const std::size_t entry_size = pixl_entry_get_len(entry,data,size);
			proxies.emplace_back(view<const uint8_t>(data,entry_size,entry_offset),path);
			
		});
	}

	
	/** @see void open(const uint8_t*,size_t)
	 *  @see PackReader::PackReader(const std::vector<uint8_t>&)
	 */
	void open(const std::vector<uint8_t>& pack_data)
	{
		open(pack_data.data(),pack_data.size());
	}
	
    /** @see void open(const uint8_t*,size_t)
	 *  @see PackReader::PackReader(const view<uint8_t>&)
	 */
    void open(const view<const uint8_t>& pack_data)
	{
		open(pack_data.data(),pack_data.size());
	}
	
	std::list<proxy>::const_iterator begin() const
    {
	    return proxies.begin();
    }

	std::list<proxy>::const_iterator end() const
    {
	    return proxies.end();
    }

	/**@brief gets an entry by filename
	 * @param path the filename / descriptor you wish to search for
	 * @returns the proxy to the entry if found otherwise a proxy where proxy::valid() == false
	 * @see proxy
	 */
	proxy filter(const std::string& path)
    {
    	for(const proxy& prx : *this)
    		if(prx.path() == path) return prx;
    		
    	return proxy{};    	
    }
	
private:
	std::list<proxy> proxies;
	pixl_pack_read_context context{};
	const uint8_t* data{};
	std::size_t size{};

};

/**@class PackWriter
 * @brief a minimal wrapper around pixl_pack_write_context
 */
class PackWriter
{
public:
    using view_type = view<const uint8_t>;

	/**@brief adds a new entry to the context
	 * @param v the data you want to insert
	 * @param name the descriptor / path you want to insert it with
	 */
	void insert(const std::vector<uint8_t>& v,const std::string& name)
	{
        views.emplace_back(name, view_type{v.data(),v.size()});
	}
	/**@brief adds a new entry to the context
	 * @param v the data you want to insert
	 * @param name the descriptor / path you want to insert it with
	 */
	void insert(const view<const uint8_t>& v,const std::string& name)
	{
		views.emplace_back(name,v)	;
	}
	/**@brief adds a new entry to the context
	 * @param data the data you want to insert
	 * @param size the size of the data you want to insert
	 * @param name the descriptor / path you want to insert it with
	 */
	void insert(const uint8_t* data,size_t size,const std::string& name)
	{
        views.emplace_back(name,view_type{data,size});
	}

	/**@brief generates the archive and returns it
	 * @return view_type a view onto the data with ref_counting on,
	 * as long as the view is in scope the data is valid afterwards it will be deleted
	 * (note copying or moving is possible and will keep the data intact)
	 */
	view_type generate() const
	{
		auto context = pixl_pack_gen_write_context();

        for(auto & pair : views)
        {
        	auto& name = pair.first;
        	auto& view = pair.second;
			pixl_write_entry(&context,view.begin(),view.size(),name.c_str());
        }


		std::size_t size = pixl_write_context_required_size(&context);
		std::uint8_t* data = pixl_write_context_assemble(&context);

		return view_type{data,size,0,true};
	}

private:
	std::list<std::pair<std::string,view_type>> views;
};
#endif
}} //namespace pixl::util
#endif

#undef PIXL_INTERNAL_ALLOC
#undef PIXL_INTERNAL_ALLOC_ARRAY
#undef PIXL_INTERNAL_FREE
#undef PIXL_INTERNAL_FREE_ARRAY
#undef PIXL_NULL 
#undef PIXL_PTR_CAST
#undef PIXL_CAST
#undef PIXL_CONST
#undef PIXL_MUTABLE

#endif