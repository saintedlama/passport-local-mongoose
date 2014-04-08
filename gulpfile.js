var gulp = require('gulp');
var p = require('gulp-load-tasks')();

var path = {
    source : 'lib/*.js',
    tests : 'test/*.js'
};

gulp.task('doc', function() {
    return gulp.src(path.source)
        .pipe(p.docco())
        .pipe(gulp.dest('docs'));
});

gulp.task('test', function() {
    return gulp.src(path.tests)
        .pipe(p.mocha({ reporter : 'spec' }));
});

gulp.task('build', ['doc', 'test'], function() {
});

gulp.task('clean', function() {
    return gulp.src('docs')
        .pipe(p.clean());
});

gulp.task('default', ['clean'], function() {
    gulp.start('build');
});
