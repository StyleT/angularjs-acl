var fs = require('fs');

// Include gulp
var gulp = require('gulp');

// Include Our Plugins
var jshint = require('gulp-jshint');
var concat = require('gulp-concat');
var path = require('path');
var cache = require('gulp-cache');
var angularFilesort = require('gulp-angular-filesort');
var ngAnnotate = require('gulp-ng-annotate');

// Check for "TRUE" code style in JS files
gulp.task('lint', function () {
    var jshintVersion = '2.4.1',
        jshintOptions = fs.readFileSync('.jshintrc');
    function makeHashKey(file) {
        // Key off the file contents, jshint version and options
        return [file.contents.toString('utf8'), jshintVersion, jshintOptions].join('');
    }

    return gulp.src([
        './src/**/*.js'
    ])
        .pipe(cache(jshint('.jshintrc'), {
            key: makeHashKey,
            // What on the result indicates it was successful
            success: function (jshintedFile) {
                return jshintedFile.jshint.success;
            },
            // What to store as the result of the successful action
            value: function(jshintedFile) {
                // Will be extended onto the file object on a cache hit next time task is ran
                return {
                    jshint: jshintedFile.jshint
                };
            }
        }))
        .pipe(jshint.reporter('default'))
        .pipe(jshint.reporter('fail'));
});

gulp.task('compile', function () {
    return gulp.src('./src/**/*.js')
        .pipe(angularFilesort())
        .pipe(ngAnnotate())
        .pipe(concat('acl.js'))
        .pipe(gulp.dest('./dist'));
});

gulp.task('test', ['lint', 'compile'], function (done) {
    var karmaServer = require('karma').Server;

    new karmaServer({
        configFile: __dirname + '/karma.conf.js',
        browsers: ['PhantomJS']
    }, done).start();
});

gulp.task('generate-doc', function () {
    var gulpDocs = require('gulp-ngdocs');
    return gulp.src('./src/**/*.js')
        .pipe(gulpDocs.process({
            html5Mode: false
        }))
        .pipe(gulp.dest('./docs'));
});


gulp.task('watch', function () {
    gulp.watch(['./lib/**/*.js'], ['lint', 'compile']);
});

gulp.task('default', ['lint', 'compile', 'watch']);