set(libs
    mbedtls
    mbedx509
    builtin
    embedded_cmp
)

add_executable(cmpclient cmpclient.c)
target_link_libraries(cmpclient ${libs})

install(TARGETS ${targets}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
        
