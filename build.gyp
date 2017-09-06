{
  'targets': [
    {
      'target_name': 'certificate_fuzzer',
      'type': 'shared_library',
      'sources': [
        '<!@(ls <(DEPTH)/src/*.cpp)',
      ],
      'libraries': [
        '-lbotan-1.10',
      ],
      'include_dirs': [
        '/usr/include/botan-1.10/'
      ],
    },
  ]
}
