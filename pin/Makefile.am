if RUST_DEBUG
    CARGO_RELEASE_ARGS=
else
    CARGO_RELEASE_ARGS=--release
endif

CARGO_VERBOSE = $(cargo_verbose_$(V))
cargo_verbose_ = $(cargo_verbose_$(AM_DEFAULT_VERBOSITY))
cargo_verbose_0 =
cargo_verbose_1 = --verbose

EXTRA_DIST = Cargo.lock
bin_PROGRAMS = pin

pin_SOURCES = Cargo.toml src/vars.rs src/main.rs src/lib.rs src/config.rs src/instapaper.rs src/pinboard.rs \
	src/url-stream.rs

pin$(EXEEXT): $(pin_SOURCES)
	cd $(top_srcdir)/pin && \
	CARGO_TARGET_DIR=@abs_top_builddir@/pin/target cargo build $(CARGO_VERBOSE) $(CARGO_RELEASE_ARGS)

clean-local:
	cd $(top_srcdir)/pin && \
	CARGO_TARGET_DIR=@abs_top_builddir@/pin/target cargo clean && \
	rm -rf $(top_srcdir)/pin/target-bin

check-local:
	cd $(top_srcdir)/pin && \
	CARGO_TARGET_DIR=@abs_top_builddir@/pin/target cargo test

install-exec-local: pin$(EXEEXT)
	install -d $(DESTDIR)$(bindir)
	install -m 755 @abs_top_builddir@/pin/target/$(RUST_TARGET_SUBDIR)/pin $(DESTDIR)$(bindir)/pin

doc:
	cargo doc && \
	cargo doc --bin pin --target-dir target-bin --no-deps
