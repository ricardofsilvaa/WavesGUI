/*global module:false*/
module.exports = function (grunt) {
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        meta: {
            sources: {
                all: ['src/**/*.js'],
                prod: ['src/**/*.js', '!src/**/*.spec.js'],
                ordered: {
                    libraries: [
                        // This library doesn't work properly if included after Angular
                        'bower_components/js-sha3/src/sha3.js',

                        'bower_components/angular/angular.js',
                        'bower_components/angular-sanitize/angular-sanitize.js',
                        'bower_components/angular-mocks/angular-mocks.js',
                        'bower_components/restangular/dist/restangular.js',
                        'bower_components/underscore/underscore.js',
                        'bower_components/decimal.js/decimal.js',
                        'bower_components/Base58/Base58.js',
                        'bower_components/cryptojslib/rollups/aes.js',
                        'bower_components/cryptojslib/rollups/sha256.js',
                        'bower_components/curve25519-js/axlsign.js'
                    ],
                    local: [
                        'src/vendor/blake2b.js',
                        'src/vendor/converters.js',

                        'src/core/waves.money.js',
                        'src/core/core.module.js',
                        'src/core/core.constants.js',
                        'src/core/core.directives.module.js',
                        'src/core/core.services.module.js',
                        'src/core/core.filter.module.js',
                        'src/core/core.services.wordlist.constant.js',
                        'src/core/passphrase.service.js',
                        'src/core/account.service.js',
                        'src/core/address.service.js',
                        'src/core/crypto.service.js',
                        'src/core/asset.service.js',
                        'src/core/alias.request.service.js',
                        'src/core/unique.assets.request.service.js',
                        'src/core/leasing.request.service.js',
                        'src/core/api.service.js',
                        'src/core/utility.service.js',
                        'src/core/localstorage.chrome.service.js',
                        'src/core/localstorage.html5.service.js',
                        'src/core/storage.provider.js',
                        'src/core/formatting.service.js',
                        'src/core/formatting.filter.js',
                        'src/core/coinomat.currency.mapping.service.js',
                        'src/core/coinomat.service.js',
                        'src/core/coinomat.fiat.service.js',
                        'src/core/matcher.api.service.js',
                        'src/core/datafeed.api.service.js',
                        'src/core/matcher.request.service.js',
                        'src/core/order.price.js',
                        'src/core/sign.service.js',
                        'src/core/validate.service.js'
                    ]
                }
            },
            editor: 'gedit --new-window -s ',
            target: 'wavesplatform-core'
        },
        jshint: {
            all: ['<%= meta.sources.all %>', '!src/vendor/*.js']
        },
        jscs: {
            src: ['<%= meta.sources.all %>', '!src/vendor/*.js'],
            options: {
                config: '.jscsrc'
            }
        },
        watch: {
            scripts: {
                files: ['Gruntfile.js', '<%= meta.sources.all %>'],
                tasks: ['test'],
                options: {
                    interrupt: true
                }
            }
        },
        karma: {
            options: {
                configFile: 'karma.conf.js'
            },
            development: {
                options: {
                    files: [
                        '<%= meta.sources.ordered.libraries %>',
                        '<%= meta.sources.ordered.local %>',

                        'src/**/*.spec.js'
                    ]
                }
            },
            distr: {
                options: {
                    files: [
                        '<%= meta.sources.ordered.libraries %>',
                        'distr/<%= meta.target %>.js',
                        'src/**/*.spec.js'
                    ]
                }
            },
            minified: {
                options: {
                    files: [
                        '<%= meta.sources.ordered.libraries %>',
                        'distr/<%= meta.target %>.min.js',
                        'src/**/*.spec.js'
                    ]
                }
            }
        },
        concat: {
            distr: {
                src: ['<%= meta.sources.ordered.local %>'],
                dest: 'distr/<%= meta.target %>.js'
            }
        },
        uglify: {
            options: {
                mangle: false
            },
            distr: {
                files: {
                    'distr/<%= meta.target %>.min.js': ['distr/<%= meta.target %>.js']
                }
            }
        },
        clean: ['distr/**']
    });

    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-contrib-jasmine');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-copy');
    grunt.loadNpmTasks('grunt-contrib-compress');
    grunt.loadNpmTasks('grunt-jscs');
    grunt.loadNpmTasks('grunt-karma');

    grunt.registerTask('distr', ['clean', 'build']);
    grunt.registerTask('test', ['jshint', 'jscs', 'karma:development']);
    grunt.registerTask('build', [
        'jscs',
        'jshint',
        'karma:development',
        'concat',
        'karma:distr',
        'uglify',
        'karma:minified'
    ]);
};
