{
  'targets': [
    {
      'target_name': 'kerberos',      
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'conditions': [
        ['OS=="mac"', {
          'sources': [ 'lib/kerberos.cc', 'lib/worker.cc', 'lib/kerberosgss.c', 'lib/base64.c', 'lib/kerberos_context.cc' ],
          'defines': [
            '__MACOSX_CORE__'
          ],
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
          },
          "link_settings": {
            "libraries": [
              "-lkrb5"
            ]
          }
        }],
        ['OS=="win"',  {
          'sources': [ 
            'lib/win32/kerberos.cc', 
            'lib/win32/base64.c', 
            'lib/win32/worker.cc',
            'lib/win32/kerberos_sspi.c',
            'lib/win32/wrappers/security_buffer.cc',
            'lib/win32/wrappers/security_buffer_descriptor.cc',
            'lib/win32/wrappers/security_context.cc',
            'lib/win32/wrappers/security_credentials.cc'
          ],          
          "link_settings": {
            "libraries": [
            ]
          }
        }]
      ]
    }
  ]
}