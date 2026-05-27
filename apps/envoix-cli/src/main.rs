fn main() {
    let mut args = std::env::args();
    let _program = args.next();

    match args.next().as_deref() {
        Some("-h" | "--help") | None => print_help(),
        Some(command) => {
            eprintln!("unknown command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "envoix CLI\n\
         \n\
         Usage:\n\
           envoix --help\n\
         \n\
         Commands:\n\
           send       planned\n\
           receive    planned"
    );
}
