use log::{Metadata, Record};

pub struct SpLogger;

impl log::Log for SpLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            ffa::println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
