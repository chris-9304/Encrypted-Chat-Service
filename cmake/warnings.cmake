function(cloak_target_warnings tgt)
    target_compile_options(${tgt} PRIVATE
        /W4
        /WX
        /permissive-
        /Zc:__cplusplus
        /Zc:preprocessor
    )
endfunction()
