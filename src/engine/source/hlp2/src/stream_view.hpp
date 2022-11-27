#ifndef WAZUH_ENGINE_STREAM_VIEW_HPP
#define WAZUH_ENGINE_STREAM_VIEW_HPP

#include <cstring>
#include <streambuf>

template<typename _char_type, class _traits_type >
class view_streambuf final: public std::basic_streambuf<_char_type, _traits_type > {
private:
    typedef std::basic_streambuf<_char_type, _traits_type > super_type;
    typedef view_streambuf<_char_type, _traits_type> self_type;
public:

    /**
    *  These are standard types.  They permit a standardized way of
    *  referring to names of (or names dependent on) the template
    *  parameters, which are specific to the implementation.
     */
    typedef typename super_type::char_type char_type;
    typedef typename super_type::traits_type traits_type;
    typedef typename traits_type::int_type int_type;
    typedef typename traits_type::pos_type pos_type;
    typedef typename traits_type::off_type off_type;

    typedef typename std::basic_string_view<char_type, traits_type> source_view;

    view_streambuf(const source_view& src) noexcept:
        super_type(),
        src_( src )
    {
        char_type *buff = const_cast<char_type*>( src_.data() );
        this->setg( buff , buff, buff + src_.length() );
    }

    virtual std::streamsize xsgetn(char_type* __s, std::streamsize __n) override
    {
        if(0 == __n)
            return 0;
        if( (this->gptr() + __n) >= this->egptr() ) {
            __n =  this->egptr() - this->gptr();
            if(0 == __n && !traits_type::not_eof( this->underflow() ) )
                return -1;
        }
        std::memmove( static_cast<void*>(__s), this->gptr(), __n);
        this->gbump( static_cast<int>(__n) );
        return __n;
    }

    virtual int_type pbackfail(int_type __c) override
    {
        char_type *pos = this->gptr() - 1;
        *pos = traits_type::to_char_type( __c );
        this->pbump(-1);
        return 1;
    }

    virtual int_type underflow() override
    {
        return traits_type::eof();
    }

    virtual std::streamsize showmanyc() override
    {
        return static_cast<std::streamsize>( this->egptr() - this->gptr() );
    }

    virtual ~view_streambuf() override
    {}
private:
    const source_view& src_;
};

template<typename _char_type>
class view_istream final:public std::basic_istream<_char_type, std::char_traits<_char_type> > {
    view_istream(const view_istream&) = delete;
    view_istream& operator=(const view_istream&) = delete;
private:
    typedef std::basic_istream<_char_type, std::char_traits<_char_type> > super_type;
    typedef view_streambuf<_char_type, std::char_traits<_char_type> > streambuf_type;
public:
    typedef _char_type  char_type;
    typedef typename super_type::int_type int_type;
    typedef typename super_type::pos_type pos_type;
    typedef typename super_type::off_type off_type;
    typedef typename super_type::traits_type traits_type;
    typedef typename streambuf_type::source_view source_view;

    view_istream(const source_view& src):
        super_type( nullptr ),
        sb_(nullptr)
    {
        sb_ = new streambuf_type(src);
        this->init( sb_ );
    }


    view_istream(view_istream&& other) noexcept:
        super_type( std::forward<view_istream>(other) ),
        sb_( std::move( other.sb_ ) )
    {}

    view_istream& operator=(view_istream&& rhs) noexcept
    {
        view_istream( std::forward<view_istream>(rhs) ).swap( *this );
        return *this;
    }

    virtual ~view_istream() override {
        delete sb_;
    }

private:
    streambuf_type *sb_;
};


#endif // WAZUH_ENGINE_STREAM_VIEW_HPP
