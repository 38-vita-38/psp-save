set(SRCS
    chnnlsv.c
    hash.c
    main.c
    psf.c
    libkirk/AES.c
    libkirk/bn.c
    libkirk/ec.c
    libkirk/kirk_engine.c
    libkirk/SHA1.c
)

set(SRCS ${SRCS})

add_executable(psp-save ${SRCS})
