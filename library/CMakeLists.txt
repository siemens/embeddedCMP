set(embedded_cmp
    cmpcl_ctx.c
	cmpcl_lib.c
	cmpcl_read.c
	cmpcl_ses.c
	cmpcl_write.c
)

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

if(WIN32)
    set(libs ${libs} ws2_32)
endif(WIN32)

add_library(embedded_cmp STATIC embedded_cmp)
set_target_properties(embedded_cmp PROPERTIES OUTPUT_NAME embedded_cmp)
target_link_libraries(embedded_cmp ${libs})

add_custom_target(lib DEPENDS embedded_cmp)

