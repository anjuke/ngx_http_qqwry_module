ngx_http_qqwry_module
=====================

A ngnix module that creates variables with location info from QQWry.


Install
-------

    $ git clone git://github.com/anjuke/ngx_http_qqwry_module.git

    $ cd /path/to/nginx_source/
    $ ./configure --add-module=/path/to/ngx_http_qqwry_module/
    $ make
    $ sudo make install

    $ sudo cp qqwry-utf8.dat $nginx_installed/conf/

Configure
---------

    http {
        qqwry $qqwry_loc conf/qqwry-utf8.dat;
        ...
    }
Or
    http {
        qqwry $remote_addr $qqwry_loc conf/qqwry-utf8.dat;
        ...
    }

