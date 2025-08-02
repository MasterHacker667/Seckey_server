use core::hash;
use std::ffi::OsStr;
use std::os::unix::process;
use std::path::{self, Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::fs;
use std::io::{self, Write};
use std::vec;
use chrono::format::format;
use openssl::sha::Sha512;
use openssl::string;
use rand::seq::SliceRandom;
use rand::Rng;
use std::io::Read;
use hex;
use sha2:: {Sha256, Digest};
use std::process::{Command, Stdio};
use std::process::exit;
use base64::{self, write};
use rpassword::read_password;

use zip::write::FileOptions;
use walkdir::WalkDir;
use zip::ZipWriter;
use zip::read::ZipArchive;

use std::io::stdin;
struct savedUser {
    username: String, 
    password: String,
    role: char,
    salt: String
}

struct User {
    username: String,
    password: String,
    role: char
}
fn read_char() -> char {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("Error al leer");

    buffer.trim().chars().next().expect("No se ingresó ningún carácter")
}

fn login_user() -> savedUser{
    //Vamos a iniciar sesion, primero pedimos el usuario
    let mut username = String::new();
    let mut password = String::new();
    let mut rol = String::new();
    writeLog("Ingrese su nombre de usuario: \n");
    io::stdin().read_line(&mut username).expect("Error al leer el nombre de usuario");
    writeLog("Ingrese su contraseña: \n");
    password = read_password().expect("Error al leer la contraseña");
    //io::stdin().read_line(&mut password).expect("Error al leer la contraseña");
    writeLog("Ingrese su rol: \n\tA) Administrador \n\tB) Usuario \n\tC) Invitado \nSeleccione un rol: \n");
    username = username.trim().to_string();
    password = password.trim().to_string();
    loop {
        rol.clear();
        rol.push(read_char());
        if rol == "A" || rol == "B" || rol == "C" {
            break;
        } else {
            writeLog("Rol inválido. Debe ser A, B o C Inténtalo de nuevo.\n");
        }
    }
    //Ahora que ya tenemos los principales datos, debemos abrir el archivo de usuarios
    let ruta_usuarios = home_path("Server/Credentials/toffu.bin");
    if !ruta_usuarios.exists() {
        writeLog("Error: El archivo de usuarios no existe. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_usuarios).expect("Error al abrir el archivo de usuarios");
    let mut contenido = String::new();
    file.read_to_string(&mut contenido).expect("Error al leer el archivo de usuarios");
    //Ahora, los usuarios (sus datos) estan separados por un ¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢
    let usuarios: Vec<&str> = contenido.split("¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢").collect();
    let mut realUsuarios :Vec<Vec<&str>> = Vec::new();
    for i in usuarios{
        let mut datos: Vec<&str> = i.split("\n").collect();
        if datos[datos.len() -1].len() == 0{
            datos.pop();
            
        }
        //println!("{:?}", datos.len());
        if datos[0] == ""{
            datos.remove(0);
        }

        
        if datos != vec![""] && datos.len() > 3 && datos.len() != 2 {
            realUsuarios.push(datos);
        }
        
    }
    //Debemos limpiar los espacios en blanco y los vectores conformados solo por estos

    //En cada "usuario" que tenemos, [0] es el username, [1] es el password, [2] es el rol cifrado, [3] es el salt
    
    //Necesitamos tomar el iv y la llaves AES del servidor para descifrar el ROL
    let iv_path = home_path("Server/IVGenServer/presentacion1.pptx");
    if !iv_path.exists() {
        writeLog("Error: No se encontró el IV. \n");
        exit(0);
    }
    let aes_path = home_path("Server/AESKeyServer/presentacion2.pptx");
    if !aes_path.exists() {
        writeLog("Error: No se encontró la llave AES. \n");
        exit(0);
    }
    //Leemos el IV del archivo
    let iv = fs::read_to_string(iv_path).expect("Error al leer el IV");
    //Leemos la llave AES del archivo
    let aes_key = fs::read_to_string(aes_path).expect("Error al leer la llave AES");
    //Convertimos el IV y la llave AES a bytes
    let iv_bytes = base64::decode(iv).expect("Error al decodificar el IV");
    let aes_key_bytes = base64::decode(aes_key).expect("Error al decodificar la llave AES");

    //Ahora debemos hashear el username y la contraseña con el salt como se hizo en el create_user
    //println!("{:?}", realUsuarios);
    let mut theUser = savedUser {
        username: String::new(),
        password: String::new(),
        role: '\0',
        salt: String::new() // El salt no lo necesitamos aquí, ya que lo vamos a descifrar
    };
    let mut termi = false;
    for i in realUsuarios{
        let mut hasher = Sha256::new();
        let mut hasher2 = Sha256::new();
        let nUser = format!("{}{}", username, i[3]);
        let nPassword = format!("{}{}", password, i[3]);
        //println!("Username: {}\nPassword: {}", nUser, nPassword);
        hasher.update(nUser.as_bytes());
        hasher2.update(nPassword.as_bytes());
        let user_hashed = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let password_hashed = hasher2.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        if i[0] == user_hashed && i[1] == password_hashed {
            //Ahora debemos descifrar el rol con AES, usando la llave AES y el IV
            let mut cipher = openssl::symm::Crypter::new(
                openssl::symm::Cipher::aes_256_cbc(),
                openssl::symm::Mode::Decrypt,
                &aes_key_bytes,
                Some(&iv_bytes),
            ).expect("Error al crear el descifrador AES");
            let mut decrypted_role = vec![0; i[2].len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
            let mut count = cipher.update(&base64::decode(i[2]).expect("Error al decodificar el rol cifrado"), &mut decrypted_role).expect("Error al descifrar el rol");
            count += cipher.finalize(&mut decrypted_role[count..]).expect("Error al finalizar el descifrado");
            decrypted_role.truncate(count);
            let decrypted_role_string = String::from_utf8(decrypted_role).expect("Error al convertir el rol descifrado a String");
            //Comprobamos que el rol descifrado sea igual al rol ingresado
            if decrypted_role_string.chars().next().unwrap() == rol.chars().next().unwrap() {
                theUser.username = username.clone();
                theUser.password = password.clone();
                theUser.role = decrypted_role_string.chars().next().unwrap();
                theUser.salt = i[3].to_string();
                termi = true;
                
                

                break;
            }
        }

    }
    if termi {
        writeLog(&format!("Bienvenido {} con rol {} \n", username, rol));
    }else{
        writeLog("Error, Usuario inexistente\n");
        exit(0);
    }
    theUser
   
    
}

fn create_user(bandPass: bool) -> savedUser{
    let mut user : User = User {
        username: String::new(),
        password: String::new(),
        role: '\0'
    };
    let mut savedUser: savedUser = savedUser {
        username: String::new(),
        password: String::new(),
        role: '\0',
        salt: String::new()
    };
    let mut hasher = Sha256::new();
    let mut Username = String::from("");
    let mut Password = String::from("");
    let mut Password2 = String::from("");
    
    let mut Role: String = String::new();
    //let mut bandPass = true;
    //Ver si existe el archivo de usuarios
    let ruta_usuarios = home_path("Server/Credentials/toffu.bin");
    if !ruta_usuarios.exists() {
        //Si no existe, lo creamos
        let mut file = File::create(&ruta_usuarios).expect("Error al crear el archivo de usuarios");
        writeLog("Archivo de usuarios creado correctamente. \n");
    } else {
        writeLog("El archivo de usuarios ya existe. \n");
    }
    //Creamos un salt aleatorio
    
    let mut rng = rand::thread_rng();
    let salt: String = (0..16).map(|_| rng.gen_range(0..=9).to_string()).collect();
    hasher.update(salt.as_bytes());
    savedUser.salt = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    writeLog("Ingrese un nombre de usuario: \n");
    while true{
        io::stdin().read_line(&mut Username).expect("Error al leer la línea");
        if Username.trim().len() < 5 {
            writeLog("El nombre de usuario debe tener al menos 5 caracteres. Inténtalo de nuevo.\n");
            Username.clear();
        } else {
            break;
        }
    }
    writeLog("Ingrese una contraseña: \n");
    while true{
        io::stdin().read_line(&mut Password).expect("Error al leer la línea");
        if Password.trim().len() < 8 {
            writeLog("La contraseña debe tener al menos 8 caracteres. Inténtalo de nuevo.\n");
            Password.clear();
        } else{
            writeLog("Confirma la contraseña nuevamente: \n");
            io::stdin().read_line(&mut Password2).expect("Error al leer la línea");
            if Password.trim() != Password2.trim() {
                writeLog("Las contraseñas no coinciden. Inténtalo de nuevo.\n");

                Password.clear();
                Password2.clear();
            } else {
                savedUser.username = Username.trim().to_string();
                savedUser.password = Password.trim().to_string();

                break;
            }
        }
    }
    if(bandPass){
        writeLog("Ingrese el rol del usuario \n\tA) Administrador \n\tB) Usuario \n\tC) Invitado \nSelecicona un rol: \n");
        loop {
            Role.clear();
            Role.push(read_char());
            if Role == "A" || Role == "B" || Role == "C" {
                savedUser.role = Role.chars().next().unwrap();
                break;
            } else {
                writeLog("Rol inválido. Debe ser A, B o C Inténtalo de nuevo.\n");
            }
        }
    }else{
        //Si no es bandPass, entonces el rol es A
        savedUser.role = 'A';
    }
    //Creamos el "json" de datos:
    writeLog(format!("Usuario {} con rol {} creado correctamente. \n", savedUser.username, savedUser.role).as_str());
    //Ahora debemos concatenar el username con el salt
    let mut hasher1 = Sha256::new();
    let concatUserSalt = format!("{}{}", savedUser.username, savedUser.salt);
    //println!("ConcatUserSalt: {}", concatUserSalt);
    hasher1.update(concatUserSalt.as_bytes());
    user.username = hasher1.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    //println!("Username hasheado: {}", user.username);

    //Ahora debemos hashear la contraseña con el salt
    let mut hasher2 = Sha256::new();
    let concatPassSalt = format!("{}{}", savedUser.password, savedUser.salt);
    //println!("ConcatPassSalt: {}", concatPassSalt);
    hasher2.update(concatPassSalt.as_bytes());
    user.password = hasher2.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    //println!("Password hasheado: {}", user.password);
    //Ahora debemos Cifrar el rol con AES, usando la llave AES generada anteriormente
    let aes_key_path = home_path("Server/AESKeyServer/presentacion2.pptx");
    if !aes_key_path.exists() {
        writeLog("Error: No se encontró la llave AES. \n");
        exit(0);
    }
    let aes_key = fs::read_to_string(aes_key_path).expect("Error al leer la llave AES");
    let aes_key_bytes = base64::decode(aes_key).expect("Error al decodificar la llave AES");
    let mut aes = openssl::symm::Cipher::aes_256_cbc();
    //Necesitamos el IV para el cifrado, el que generamos anteriormente
    let iv_path = home_path("Server/IVGenServer/presentacion1.pptx");
    if !iv_path.exists() {
        writeLog("Error: No se encontró el IV. \n");
        exit(0);
    }
    //Leemos el IV del archivo
    let iv = fs::read_to_string(iv_path).expect("Error al leer el IV");
    let iv_bytes = base64::decode(iv).expect("Error al decodificar el IV");
    //Ciframos el rol
    let mut cipher = openssl::symm::Crypter::new(
        aes,
        openssl::symm::Mode::Encrypt,
        &aes_key_bytes,
        Some(&iv_bytes),
    ).expect("Error al crear el cifrador AES");
    let mut encrypted_role = vec![0; 1 + aes.block_size()];
    let mut count = cipher.update(savedUser.role.to_string().as_bytes(), &mut encrypted_role).expect("Error al cifrar el rol");
    count += cipher.finalize(&mut encrypted_role[count..]).expect("Error al finalizar el cifrado");
    encrypted_role.truncate(count);
    //Convertimos el rol cifrado a base64
    let encrypted_role_base64 = base64::encode(&encrypted_role);
    //Hagamos una prueba para desencriptar el rol
    //MARCA1
    /*let mut decipher = openssl::symm::Crypter::new(
        aes,
        openssl::symm::Mode::Decrypt,
        &aes_key_bytes,
        Some(&iv_bytes),
    ).expect("Error al crear el descifrador AES");
    let mut decrypted_role = vec![0; encrypted_role.len() + aes.block_size()];
    let mut count = decipher.update(&encrypted_role, &mut decrypted_role).expect("Error al descifrar el rol");
    count += decipher.finalize(&mut decrypted_role[count..]).expect("Error al finalizar el descifrado");
    decrypted_role.truncate(count);
    //Convertimos el rol descifrado a String
    let decrypted_role_string = String::from_utf8(decrypted_role).expect("Error al convertir el rol descifrado a String");
    //Comprobamos que el rol descifrado sea igual al rol original
    if decrypted_role_string == savedUser.role.to_string() {
        writeLog("El rol cifrado y descifrado coincide correctamente. \n");
    } else {
        writeLog("Error: El rol cifrado y descifrado no coincide. \n");
        return;
    }*/
    //Imprimimos el rol cifrado
    //writeLog(&format!("Rol cifrado: {}\n", encrypted_role_base64));
    //Ahora hacemos una variable que guardara todos los datos:
    let user_data = format!("{}\n{}\n{}\n{}\n¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢", user.username, user.password, encrypted_role_base64, savedUser.salt);
    //Imprimimos el rol descifrado
    //writeLog(&format!("Rol descifrado: {}\n", decrypted_role_string));
    //Procedemos a guardar esto en el archivo de usuarios
    let mut file = OpenOptions::new()
        .append(true)
        .open(&ruta_usuarios)
        .expect("Error al abrir el archivo de usuarios");
    writeln!(file, "{}", user_data).expect("Error al escribir en el archivo de usuarios");
    writeLog("Usuario guardado correctamente en el archivo de usuarios. \n");
    //Devolvemos el usuario creado en savedUser
    return savedUser;

}

fn writeLog(mensaje: &str) {
    //Sacamos la fecha de hoy
    let fecha = chrono::Local::now().format("%Y-%m-%d_%H").to_string();
    let ruta_log = format!("src/logs/{}.log", fecha);
    //Vemos si este archivo ya existe si tiene el mismo nombre (osea la fecha)
    let now = chrono::Local::now();
    let hora = now.format("[%H: %M: %S]").to_string();
    if Path::new(&ruta_log).exists() {
        //Si ya existe entonces lo abrimos y escribimos al final
        let mut file = OpenOptions::new()
            .append(true)
            .open(&ruta_log)
            .expect("Error al abrir el archivo de log");
        writeln!(file, "{}\n--------------------------------------------------\n{}\n--------------------------------------------------\n", hora, mensaje).expect("Error al escribir en el archivo de log");
        //println!("Log escrito en: {}", ruta_log);
    } else {
        let mut file = File::create(&ruta_log).expect("Error al crear el archivo de log");
        writeln!(file, "{}\n--------------------------------------------------\n{}\n--------------------------------------------------\n", hora, mensaje).expect("Error al escribir en el archivo de log");    }
    print!("{}", mensaje);
    
    //println!("Log escrito en: {}", ruta_log);

}


fn mixImagePhrase(imagen: String, frase: String) -> String{
    //A mezclar la imagen con la frase
    //Pasamos la frase a bytes
    let frase_bytes = frase.as_bytes();
    //Convertimos estos bytes a base64
    let frase_base64 = base64::encode(frase_bytes);
    //Ahora mezclamos la imagen con la frase
    let mut vectordeposiciones: Vec<usize> = vec![];
    //Seleccionar posiciones aleatorias en la imagen para insertar la frase
    for i in 0..=frase_base64.len()-1{
        //Vamos a elegir numeros aleatorios entre 0 y la longitud de la imagen
        let mut rng = rand::thread_rng();
        let posicion = rng.gen_range(0..=imagen.len()-1);
        vectordeposiciones.push(posicion);
    }
    let mut cadenaN = imagen.clone();
    let mut ih = 0; 
    for i in vectordeposiciones{
        cadenaN = format!("{}{}{}", &cadenaN[..i], &frase_base64.chars().nth(ih).expect("No hay caracteres"), &cadenaN[i..]);
    }

    return cadenaN;
}
fn createPhrase() -> String {
    let mut rng = rand::thread_rng();
    let numero = rng.gen_range(10..=20);
    let mut fraseFinal: String = String::new();
    writeLog("Ingrese una frase de seguridad: \n");
    for i in 0..=numero {
        //Por cada vuelta pedir al usuario una frase de seguridad
        writeLog(&format!("[{} / {}] ...\n", i+1, numero + 1));
        let mut frase = String::new();
        //Longitud de la frase (si es mayor a 50 caracteres, entonces se agrega, si no, se pide de nuevo)
        while frase.len() < 50{
            io::stdin().read_line(&mut frase).expect("Error al leer la línea");
            if frase.len() < 50 {
                writeLog(&format!("[{} / {}] La frase debe tener al menos 50 caracteres. Inténtalo de nuevo.\n", i+1, numero + 1));
            }
        }
        

        frase = frase.trim().to_string();
        fraseFinal.push_str(&frase);
        fraseFinal.push('\n'); // Añadir un espacio entre frases
    }
    return fraseFinal;
}
fn home_path(ruta_relativa: &str) -> PathBuf {
    let mut ruta = dirs::home_dir().expect("No se pudo obtener el home directory");
    ruta.push(ruta_relativa);
    ruta
}

fn create_admin_server() -> savedUser{
    //Ver si existe la carpeta Server en home
    writeLog("Creando el servidor de administración... \n");
    let ruta_server = home_path("Server");
    let mut exists = false;
    if !ruta_server.exists() {
        //Crear la carpeta Server si no existe
        std::fs::create_dir_all(&ruta_server).expect("Error al crear la carpeta Server");
        writeLog("Carpeta Server creada correctamente. \n");
    } else {
        writeLog("La carpeta Server ya existe. \n");
        exists = true;
    }
    

    //Crear carpeta de imagenes si no existe
    let ruta_imagenes = home_path("Sofia/Images");
    if !ruta_imagenes.exists() {
        std::fs::create_dir_all(&ruta_imagenes).expect("Error al crear la carpeta de imágenes");
        writeLog("Carpeta de imágenes creada correctamente. \n");
    }else{
        writeLog("La carpeta de imágenes ya existe. \n");
    }
    //Ingresar una frase de seguridad
    let frase = createPhrase();
    //Imprimir la frase de seguridad
    //println!("Frase de seguridad ingresada: {}", frase);
    //USO DE LA IMAGEN
    //Primero debemos ver que la carpeta no este vacía
    let ruta_imagenes = home_path("Sofia/Images");
    if ruta_imagenes.read_dir().expect("Error al leer el directorio de imágenes").count() == 0 {
        //println!("La carpeta de imágenes está vacía. Por favor, añade una imagen antes de continuar.");
        //Usar la imagen del proyecto y ponerla en la carpeta de imagenes
        let ruta_proyecto_imagen = Path::new("src/assets/imagenDefault.jpg");
        let ruta_destino = home_path("Sofia/Images/imagenDefault.jpg");
        std::fs::copy(ruta_proyecto_imagen, &ruta_destino).expect("Error al copiar la imagen por defecto");
        writeLog("Imagen por defecto copiada a la carpeta de imágenes. \n");

    }
    //mostrar archivos en la carpeta de imagenes
    writeLog("Archivos en la carpeta de imágenes: \n");
    let mut seleccionado: Option<PathBuf> = None;
    let mut contar = 0;
    let mut imagenes: Vec<PathBuf> = Vec::new();
    for entry in ruta_imagenes.read_dir().expect("Error al leer el directorio de imágenes") {
        let entry = entry.expect("Error al obtener la entrada del directorio");
        let path = entry.path();
        
        if path.is_file() {
            //println!("{}", path.display()); 
            imagenes.push(path);
            contar +=1;
        }
    }
    let mut rng = rand::thread_rng();
    let mut numero = rng.gen_range(0..=imagenes.len() - 1);
    let imagen_seleccionada = imagenes.choose(&mut rng).expect("El vector está vacío");
    let imagenseleccionada =imagen_seleccionada.display().to_string();
    //println!("Imagen seleccionada: {}", imagenseleccionada);
    //Leer la imagen seleccionada 
    let mut file = File::open(imagenseleccionada).expect("Error al abrir la imagen seleccionada");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error al leer la imagen seleccionada");
    //Convertir la imagen a base64
    let imagen_base64 = base64::encode(&buffer);
    //Imprimir la imagen en base64
    //println!("Imagen en base64: {}", imagen_base64);

    //Ahora debemos mexclar la imagen_base64 con la frase
    let imagen_mezclada = mixImagePhrase(imagen_base64, frase);
    //Pasarla a bytes
    let imagen_bytes = imagen_mezclada.as_bytes();
    //Crear la carpeta de credenciales si no existe
    let ruta_credenciales = home_path("Server/Credentials");
    if !ruta_credenciales.exists() {
        std::fs::create_dir_all(&ruta_credenciales).expect("Error al crear la carpeta de credenciales");
    }
    //Crear el archivo de imagen mezclada
    let ruta_imagen_mezclada = home_path("Server/Credentials/Patricia.love");
    let mut file = File::create(&ruta_imagen_mezclada).expect("Error al crear el archivo de imagen mezclada");
    file.write_all(imagen_bytes).expect("Error al escribir la imagen mezclada");
    writeLog("Imagen mezclada creada y guardada correctamente. \n");
    //AHora a generar el IV INICIAL 
    let mut ivHash = Sha256::new();
    ivHash.update(imagen_bytes);
    let iv = ivHash.finalize();
    //convertir el IV a base64
    let iv_base64 = base64::encode(iv);
    //Crear el archivo de IV
    let ruta_iv = home_path("Server/IVGenServer/presentacion1.pptx");
    if !ruta_iv.exists() {
        //Crear la carpeta si no existe
        std::fs::create_dir_all(home_path("Server/IVGenServer")).expect("Error al crear la carpeta IVGenServer");
        //Crear el archivo de IV
        let mut file = File::create(&ruta_iv).expect("Error al crear el archivo de IV");
        file.write_all(iv_base64.as_bytes()).expect("Error al escribir el IV");
        writeLog("IV generado y guardado correctamente. \n");
    }else{
        writeLog("El archivo de IV ya existe. No se generará uno nuevo. \n");
    }

    //Ahora a generar la clave AES
    let mut aesHash = Sha256::new();
    //concatenar la imagen mezclada y el IV
    let semilla = format!("{}{}", imagen_mezclada, iv_base64);
    aesHash.update(semilla.as_bytes());
    let aes_key = aesHash.finalize();
    //convertir la clave AES a base64
    let aes_key_base64 = base64::encode(aes_key);
    //Crear el archivo de clave AES
    let ruta_aes_key = home_path("Server/AESKeyServer/presentacion2.pptx");
    if !ruta_aes_key.exists() {
        //Crear la carpeta si no existe
        std::fs::create_dir_all(home_path("Server/AESKeyServer")).expect("Error al crear la carpeta AESKeyServer");
    }else{
        writeLog("El archivo de clave AES ya existe. No se generará uno nuevo. \n");
    }
    //Crear el archivo de clave AES
    let mut file = File::create(&ruta_aes_key).expect("Error al crear el archivo de clave AES");
    file.write_all(aes_key_base64.as_bytes()).expect("Error al escribir la clave AES");
    writeLog("Clave AES generada y guardada correctamente. \n");

    //Ahora debemos sacar la iv de su archivo y hashearla
    let mut iv_file = File::open(&ruta_iv).expect("Error al abrir el archivo de IV");
    let mut iv_buffer = String::new();
    iv_file.read_to_string(&mut iv_buffer).expect("Error al leer el archivo de IV");
    //Hashear el IV
    let mut iv_hash = Sha256::new();
    iv_hash.update(iv_buffer.as_bytes());
    let iv_hash_result = iv_hash.finalize();
    //Convertir el hash del IV a base64
    let iv_hash_base64 = base64::encode(iv_hash_result);
    //Crear el archivo de hash del IV
    let ruta_iv_hash = home_path("Server/Credentials/presentacion1Sign.pp");
    if !ruta_iv_hash.exists() {
        //Crear la carpeta si no existe
        std::fs::create_dir_all(home_path("Server/Credentials")).expect("Error al crear la carpeta Credentials");
    }else{
        writeLog("El archivo de hash del IV ya existe. No se generará uno nuevo. \n");
    }
    //Crear el archivo de hash del IV
    let mut file = File::create(&ruta_iv_hash).expect("Error al crear el archivo de hash del IV");
    file.write_all(iv_hash_base64.as_bytes()).expect("Error al escribir el hash del IV");
    writeLog("Hash del IV generado y guardado correctamente. \n");

    //Ahora debemos sacar la clave AES de su archivo y hashearla
    let mut aes_file = File::open(&ruta_aes_key).expect("Error al abrir el archivo de clave AES");
    let mut aes_buffer = String::new();
    aes_file.read_to_string(&mut aes_buffer).expect("Error al leer el archivo de clave AES");
    //Hashear la clave AES
    let mut aes_hash = Sha256::new();
    aes_hash.update(aes_buffer.as_bytes());
    let aes_hash_result = aes_hash.finalize();
    //Convertir el hash de la clave AES a base64    
    let aes_hash_base64 = base64::encode(aes_hash_result);
    //Crear el archivo de hash de la clave AES
    let ruta_aes_hash = home_path("Server/Credentials/presentacion2Sign.pp");
    if !ruta_aes_hash.exists() {
        //Crear la carpeta si no existe
        std::fs::create_dir_all(home_path("Server/Credentials")).expect("Error al crear la carpeta Credentials");
    }else{
        println!("El archivo de hash de la clave AES ya existe. No se generará uno nuevo.");
        writeLog("El archivo de hash de la clave AES ya existe. No se generará uno nuevo. \n");
    }
    //Crear el archivo de hash de la clave AES
    let mut file = File::create(&ruta_aes_hash).expect("Error al crear el archivo de hash de la clave AES");
    file.write_all(aes_hash_base64.as_bytes()).expect("Error al escribir el hash de la clave AES");
    writeLog("Hash de la clave AES generado y guardado correctamente. \n");

    //Ahora debemos generar 2 llaves para RSA (publica y privada)
    //Usaremos openssl para generar las llaves
    let output = std::process::Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(home_path("Server/Credentials/private_key.pem"))
        .arg("2048")
        .output()
        .expect("Error al ejecutar openssl para generar la llave privada");
    if output.status.success() {
        writeLog("Llave privada generada correctamente. \n");
    } else {
        //eprintln!("Error al generar la llave privada: {}", String::from_utf8_lossy(&output.stderr));
        writeLog(&format!("Error al generar la llave privada: {} \n", String::from_utf8_lossy(&output.stderr)));
    }
    let output = std::process::Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(home_path("Server/Credentials/private_key.pem"))
        .arg("-pubout")
        .arg("-out")
        .arg(home_path("Server/Credentials/public_key.pem"))
        .output()
        .expect("Error al ejecutar openssl para generar la llave pública");
    if output.status.success() {
        writeLog("Llave pública generada correctamente. \n");
    } else {
        //eprintln!("Error al generar la llave pública: {}", String::from_utf8_lossy(&output.stderr));
        writeLog(&format!("Error al generar la llave pública: {} \n", String::from_utf8_lossy(&output.stderr)));
    }
    //Aqui procedemos a crear el archivo de las hijas
    //fs::create_dir_all(parent).expect("No se pudo crear el directorio");
    let rutaDaught = home_path("Server/myDaughter");
    std::fs::create_dir_all(&rutaDaught).expect("Error al crear la carpeta myDaughter dentro de Server");
    let rutaDaught = home_path("Server/myDaughter/mycooldaughter.yaml");
    let mut file = File::create(&rutaDaught).expect("Error al crear el archivo vacío");
    file.write_all(String::from("").as_bytes()).expect("Error al escribir Nada");
    // //Probando algoritmo y llaves
    // let mensaje = "Este es un mensaje de prueba";
    // fs::write(home_path("Server/Credentials/mensajePrueba.txt"), mensaje).expect("No se pudo guardar el mensaje");
    // // Cifrar el mensaje con la llave pública
    // let output = Command::new("openssl")
    //     .arg("pkeyutl")
    //     .arg("-encrypt")
    //     .arg("-inkey")
    //     .arg(home_path("Server/Credentials/public_key.pem"))
    //     .arg("-pubin")
    //     .arg("-in")
    //     .arg(home_path("Server/Credentials/mensajePrueba.txt"))
    //     .arg("-out")
    //     .arg(home_path("Server/Credentials/encrypted_message.bin"))
    //     .stdin(Stdio::piped())
    //     .output()
    //     .expect("Error al cifrar el mensaje con la llave pública");
    // if output.status.success() {
    //     println!("Mensaje cifrado correctamente.");
    // } else {
    //     eprintln!("Error al cifrar el mensaje: {}", String::from_utf8_lossy(&output.stderr));
    // }
    // // Descifrar el mensaje con la llave privada
    // let output = Command::new("openssl")
    //     .arg("pkeyutl")
    //     .arg("-decrypt")
    //     .arg("-inkey")
    //     .arg(home_path("Server/Credentials/private_key.pem"))
    //     .arg("-in")
    //     .arg(home_path("Server/Credentials/encrypted_message.bin"))
    //     .arg("-out")
    //     .arg(home_path("Server/Credentials/decrypted_message.txt"))
    //     .output()
    //     .expect("Error al descifrar el mensaje con la llave privada");
    // Ya se generaron las Llaves RSA, las publicas, las firmas y todo, falta el archivo logo.svg el cual será el que contenga dentro un PROD=true o un PROD=false
    let ruta_logo = home_path("Server/Credentials/logo.svg");
    if !ruta_logo.exists() {
        //Crear la carpeta si no existe
        std::fs::create_dir_all(home_path("Server/Credentials")).expect("Error al crear la carpeta Credentials");
        //Crear el archivo logo.svg
        let mut file = File::create(&ruta_logo).expect("Error al crear el archivo logo.svg");
        //Escribir dentro del archivo logo.svg el PROD=true
        file.write_all(b"PROD=false")
            .expect("Error al escribir en el archivo logo.svg");
        writeLog("Archivo logo.svg creado correctamente con PROD=false. \n");
    } else {
        writeLog("El archivo logo.svg ya existe. No se generará uno nuevo. \n");
    }
    if exists {
        writeLog("\x1b[32;1m✔ Servidor actualizado correctamente.\x1b[0m \n");
        //Devolver None
        return savedUser {
            username: String::new(),
            password: String::new(),
            role: '\0',
            salt: String::new()
        };
    } else {
        //Crear un usuario administrador
        //Dejaremos este espacio listo para hacer pull de la app en github
        writeLog("\x1b[34;1m★ Servidor de administración creado correctamente.\x1b[0m \n");
        return create_user(false);
    }

}
//A continuacion haremos las funciones que ejecutaran los comandos del servidor
fn rotIV(){
    /*Pasos a ejecutar en este proceso
        1. Generar un nuevo IV a partir del viejo IV + un numero aleatrio + la imagen mezclada
        2. Usar el viejo IV para descifrar el rol de los usuarios
        3. Cifrar los roles de los usuarios con el nuevo IV
        4. Guardar el nuevo IV en el archivo de IV el cual se encuentra en Server/IVGenServer/presentacion1.pptx
        5. Modificar la firma del IV en el archivo de firma del IV el cual se encuentra en Server/Credentials/presentacion1Sign.pp
    */
    //Primero debemos leer la imagen mezclada
    let ruta_imagen_mezclada = home_path("Server/Credentials/Patricia.love");
    if !ruta_imagen_mezclada.exists() {
        writeLog("Error: No se encontró el archivo de imagen mezclada. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_imagen_mezclada).expect("Error al abrir el archivo de imagen mezclada");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error al leer el archivo de imagen mezclada");
    //Convertir la imagen a base64
    let imagen_base64 = base64::encode(&buffer);
    //Ahora debemos mezclar la imagen con un numero aleatorio
    let mut rng = rand::thread_rng();
    let numero_aleatorio = rng.gen_range(1000..9999);
    let imagen_mezclada = mixImagePhrase(imagen_base64, numero_aleatorio.to_string());
    //Pasar la imagen mezclada a bytes
    //let imagen_bytes = imagen_mezclada.as_bytes();
    //Ahora debemos leer el IV actual
    let ruta_iv = home_path("Server/IVGenServer/presentacion1.pptx");
    if !ruta_iv.exists() {
        writeLog("Error: No se encontró el archivo de IV. \n");
        exit(0);
    }
    let mut iv_file = File::open(&ruta_iv).expect("Error al abrir el archivo de IV");
    let mut iv_buffer = String::new();
    iv_file.read_to_string(&mut iv_buffer).expect("Error al leer el archivo de IV");
    let preIv = base64::decode(iv_buffer).expect("Error al decodificar el IV");
    //println!("IV actual: {:?}", preIv);
    let ivActualb64 = base64::encode(&preIv);
    let semilla = format!("{}{}{:?}", imagen_mezclada, numero_aleatorio, ivActualb64);
    //println!("Semilla para el nuevo IV: {}", semilla);
    //Ahora generamos el nuevo IV 
    let mut ivHash = Sha256::new();
    ivHash.update(semilla.as_bytes());
    let iv = ivHash.finalize();
    //println!("Nuevo IV: {:?}", iv)
    //Convertir el IV a base64
    let iv_base64 = base64::encode(iv);
    //Guardar el nuevo IV en el archivo de IV
    let mut iv_file = File::create(&ruta_iv).expect("Error al crear el archivo de IV");
    iv_file.write_all(iv_base64.as_bytes()).expect("Error al escribir en el archivo de IV");
    writeLog("Nuevo IV generado y guardado correctamente. \n");
    
    //Ahora debemos sacar los datos del usuario 
    let ruta_usuarios = home_path("Server/Credentials/toffu.bin");
    //Para este punto el archivo debe existir, si no existe es porque el sistema fue vulnerado o corrompido
    if !ruta_usuarios.exists() {
        writeLog("Error: No se encontró el archivo de usuarios. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_usuarios).expect("Error al abrir el archivo de usuarios");
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).expect("Error al leer el archivo de usuarios");
    //Ahora debemos separar los elementos de cada usuario
    let usuarios: Vec<&str> = buffer.split("¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢").collect();
    //println!("Usuarios encontrados: {:?}", usuarios);
    //Hay algo de basura, a veces hay elementos que tienen dos o un \n, hay que eliminarlos
    //LIMPIEZA
    let mut usuarios_limpios: Vec<&str> = Vec::new();
    for usuario in usuarios {
        if !usuario.trim().is_empty() {
            usuarios_limpios.push(usuario.trim());
        }
    }
    //De esta lista de usuarios, cada elemento que tiene el usuario esta dividido por \n, debemos separarlos y agruparlos en una lista, para esto debemos tener una lista cuyos elementos sean listas y estas sublistas seran los elementos del usuario
    let mut usuarios_finales: Vec<Vec<&str>> = Vec::new();
    for usuario in usuarios_limpios {
        let elementos: Vec<&str> = usuario.split("\n").collect();
        usuarios_finales.push(elementos);
    }
    //Ahora abrimos el archivo que tiene la llave AES del sistema del servidor
    let aes_key_path = home_path("Server/AESKeyServer/presentacion2.pptx");
    if !aes_key_path.exists() {
        writeLog("Error: No se encontró el archivo de llave AES. \n");
        exit(0);
    }
    let aes_key = fs::read_to_string(aes_key_path).expect("Error al leer el archivo de llave AES");
    let aes_key_bytes = base64::decode(aes_key).expect("Error al decodificar la llave AES");
    //Cada sublista tiene 4 elementos, el username, password, rol y salt, nuestro objetivo es descifrar el rol de cada usuario y mostrarlo en pantalla (por ahora)
    let mut nUsuarios: Vec<Vec<String>> = vec![];
    //Abrimos el archivo del IV
    let mut iv_file = File::open(&ruta_iv).expect("Error al abrir el archivo de IV");
    let mut iv_buffer = String::new();
    iv_file.read_to_string(&mut iv_buffer).expect("Error al leer el archivo de IV");
    //Decodificamos el IV
    let nIv = base64::decode(iv_buffer).expect("Error al decodificar el IV");
    //Ahora vamos a descifrar el rol de cada usuario
    for i in usuarios_finales {
        //Aquí vamos a descifrar el rol de cada usuario con el prevIv
        let mut cipher = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_cbc(),
            openssl::symm::Mode::Decrypt,
            &aes_key_bytes,
            Some(&preIv),
        ).expect("Error al crear el descifrador AES");
        let mut decrypted_role = vec![0; i[2].len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
        let mut count = cipher.update(&base64::decode(i[2]).expect("Error al decodificar el rol cifrado"), &mut decrypted_role).expect("Error al descifrar el rol");
        count += cipher.finalize(&mut decrypted_role[count..]).expect("Error al finalizar el descifrado");
        decrypted_role.truncate(count);
        let decrypted_role_string = String::from_utf8(decrypted_role).expect("Error al convertir el rol descifrado a String");
        //println!("Usuario: {}, Rol descifrado: {}", i[0], decrypted_role_string);
        //Cifrar los roles de los usuarios con el nuevo IV
        let mut cipher = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_cbc(),
            openssl::symm::Mode::Encrypt,
            &aes_key_bytes,
            Some(&nIv),
        ).expect("Error al crear el cifrador AES");
        let mut encrypted_role = vec![0; decrypted_role_string.len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
        let mut count = cipher.update(decrypted_role_string.as_bytes(), &mut encrypted_role).expect("Error al cifrar el rol");
        count += cipher.finalize(&mut encrypted_role[count..]).expect("Error al finalizar el cifrado");
        encrypted_role.truncate(count);
        //Convertimos el rol cifrado a base64
        let encrypted_role_base64 = base64::encode(&encrypted_role);
        //Ahora debemos modificar la firma del IV en el archivo de firma del IV
        //Una vez descifrado, debemos cifrarlo con el nuevo IV
        let mut usuarioNN: Vec<String>= vec![];
        usuarioNN.push(i[0].to_string()); //Username
        usuarioNN.push(i[1].to_string()); //Password
        usuarioNN.push(encrypted_role_base64.clone()); //Rol descifrado
        usuarioNN.push(i[3].to_string()); //Salt
        nUsuarios.push(usuarioNN);
    }
    //Crear la cadena que los contendrá:
    let mut cadenaF: String = String::new();
    for i in nUsuarios{
        let cadena = format!("{}\n{}\n{}\n{}\n¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢\n", i[0], i[1], i[2], i[3]);
        cadenaF.push_str(&cadena);
    }
    //Ahora debemos guardar esta cadena en el archivo de usuarios
    //El archivo usuarios tiene contenido, este debe ser reemplazado
    let ruta_usuarios = home_path("Server/Credentials/toffu.bin");
    if !ruta_usuarios.exists() {
        writeLog("Error: No se encontró el archivo de usuarios. \n");
        exit(0);
    }
    let mut file = File::create(&ruta_usuarios).expect("Error al crear el archivo de usuarios");
    file.write_all(cadenaF.as_bytes()).expect("Error al escribir en el archivo de usuarios");
    writeLog("Usuarios actualizados correctamente. \n");
    //Ahora debemos modificar la firma del IV en el archivo de firma del IV
    let ruta_firma_iv = home_path("Server/Credentials/presentacion1Sign.pp");
    if !ruta_firma_iv.exists() {
        writeLog("Error: No se encontró el archivo de firma del IV. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_firma_iv).expect("Error al abrir el archivo de firma del IV");
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).expect("Error al leer el archivo de firma del IV");
    //Ahora debemos hashear el nuevo IV
    let mut ivHash = Sha256::new();
    ivHash.update(nIv);
    let iv_hash = ivHash.finalize();
    //Convertir el hash en base64
    let iv_has_b64 = base64::encode(iv_hash);
    //Ahora debemos reemplazar el contenido del archivo de firma del IV con el nuevo hash
    let mut file = File::create(&ruta_firma_iv).expect("Error al crear la firma del IV");
    file.write_all(iv_has_b64.as_bytes()).expect("Error al escribir en el archivo de firma del IV");
    writeLog("Firma del IV actualizada correctamente. \n");

}
fn rotaes(){
    //Ahora vamos a rotar la llave AES del servidor
    /*
        Pasos para ejecutar este proceso:
        1. Leer la imagen mezclada
        2. Leer la actual llave AES
        3. Mezclar la imagen mezclada con un numero aleatorio + la llave AES actual
        4. hasheamos este resultado con SHA256
        5. Guardamos el resultado en el archivo de llave AES en base64
        6. Ahora, procederiamos a usar la llave AES vieja para descifrar los roles de los usuarios
        7. Ciframos los roles de los usuarios con la nueva llave AES
        8. Guardamos los roles cifrados en el archivo de usuarios
        9. Si la operacion es exitosa, se actualiza la firma del IV con el nuevo hash de la llave AES
    */
    //Lo primero es leer el IV actual y la llave AES actual
    let ruta_iv = home_path("Server/IVGenServer/presentacion1.pptx");
    if !ruta_iv.exists() {
        writeLog("Error: No se encontró el archivo de IV. \n");
        exit(0);
    }
    let mut iv_file = File::open(&ruta_iv).expect("Error al abrir el archivo del IV");
    let mut iv_buffer = String::new();
    iv_file.read_to_string(&mut iv_buffer).expect("Error al leer el archivo del IV");
    let Iv = base64::decode(iv_buffer).expect("Error al decodificar el IV");
    //Ahora obtenemos la llave AES actual de su archivo
    let aes_key_path = home_path("Server/AESKeyServer/presentacion2.pptx");
    if !aes_key_path.exists() {
        writeLog("Error: No se encontró el archivo de llave AES. \n");
        exit(0);
    }
    let aes_key = fs::read_to_string(&aes_key_path).expect("Error al leer el archivo de la llave AES");
    let aes_key_bytes = base64::decode(&aes_key).expect("Error al decodificar la llave AES");
    //Ahora debemos leer la imagen mezclada
    let ruta_imagen_mezclada = home_path("Server/Credentials/Patricia.love");
    if !ruta_imagen_mezclada.exists() {
        writeLog("Error: No se encontró el archivo de imagen mezclada. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_imagen_mezclada).expect("Error al abrir el archivo de imagen mezclada");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error al leer el archivo de imagen mezclada");
    //Convertir la imagen a base64
    let imagen_base64 = base64::encode(&buffer);
    //Ahora debemos mezclar la imagen con un numero aleatorio
    let mut rng = rand::thread_rng();
    let numero_aleatorio = rng.gen_range(1000..9999);
    let semilla = format!("{}{}{}", aes_key, imagen_base64, numero_aleatorio);
    //Ahora debemos hashear esto
    let mut aesHas = Sha256::new();
    aesHas.update(semilla.as_bytes());
    let aes_key_new = aesHas.finalize();
    //Ahora debemos tomar los datos de todos los usuarios del sistema:
    let ruta_usuarios = home_path("Server/Credentials/toffu.bin");
    if !ruta_usuarios.exists() {
        writeLog("Error: No se encontró el archivo de usuarios. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_usuarios).expect("Error al abrir el archivo de usuarios");
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).expect("Error al leer el archivo de usuarios");
    //Ahora debemos separar los elementos de cada usuario
    let usuarios: Vec<&str> = buffer.split("¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢").collect();
    //Hay algo de basura, a veces hay elementos que tienen dos o un \n,
    // hay que eliminarlos
    let mut usuarios_limpios: Vec<&str> = Vec::new();
    for usuario in usuarios {
        if !usuario.trim().is_empty() {
            usuarios_limpios.push(usuario.trim());
        } 
    }
    //Ahora debemos separar los elementos de cada usuario
    let mut usuarios_finales: Vec<Vec<&str>> = Vec::new();
    for usuario in usuarios_limpios {
        let elementos: Vec<&str> = usuario.split("\n").collect();
        usuarios_finales.push(elementos);
    }
    //Ahora vamos a descifrar el rol de cada usuario con la llave AES actual
    let mut nUsuarios: Vec<Vec<String>> = vec![];
    for i in usuarios_finales {
        //Aquí vamos a descifrar el rol de cada usuario con la llave AES actual
        let mut cipher = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_cbc(),
            openssl::symm::Mode::Decrypt,
            &aes_key_bytes,
            Some(&Iv),
        ).expect("Error al crear el descifrador AES");
        let mut decrypted_role = vec![0; i[2].len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
        let mut count = cipher.update(&base64::decode(i[2]).expect("Error al decodificar el rol cifrado"), &mut decrypted_role).expect("Error al descifrar el rol");
        count += cipher.finalize(&mut decrypted_role[count..]).expect("Error al finalizar el descifrado");
        decrypted_role.truncate(count);
        let decrypted_role_string = String::from_utf8(decrypted_role).expect("Error al convertir el rol descifrado a String");
        
        //Ya que desciframos el rol debemos cifrarlo ahora con la nueva llave AES
        let mut cipher = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_cbc(),
            openssl::symm::Mode::Encrypt,
            &aes_key_new,
            Some(&Iv),
        ).expect("Error al crear el cifrador AES");
        let mut encrypted_role = vec![0; decrypted_role_string.len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
        let mut count = cipher.update(decrypted_role_string.as_bytes(), &mut encrypted_role).expect("Error al cifrar el rol");
        count += cipher.finalize(&mut encrypted_role[count..]).expect("Error al finalizar el cifrado");
        encrypted_role.truncate(count);
        //Convertimos el rol cifrado a base64
        let encrypted_role_base64 = base64::encode(&encrypted_role);
        let usuarioNN: Vec<String> = vec![
            i[0].to_string(), //Username
            i[1].to_string(), //Password
            encrypted_role_base64.clone(), //Rol descifrado
            i[3].to_string() //Salt
        ];
        nUsuarios.push(usuarioNN);
    }
    //Una vez logrado, debemos poner la nueva llave AES en el archivo de llave AES
    let aes_key_base64 = base64::encode(aes_key_new);
    let mut file = File::create(&aes_key_path).expect("Error al crear el archivo de llave AES");
    file.write_all(aes_key_base64.as_bytes()).expect("Error al escribir en el archivo de llave AES");
    writeLog("Nueva llave AES generada y guardada correctamente. \n");
    //Ahora debemos guardar los roles cifrados en el archivo de usuarios
    let mut cadenaF: String = String::new();
    for i in nUsuarios {
        let cadena = format!("{}\n{}\n{}\n{}\n¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢\n", i[0], i[1], i[2], i[3]);
        cadenaF.push_str(&cadena);
    }
    //Ahora debemos guardar esta cadena en el archivo de usuarios, si este no existe, lo creamos
    let ruta_usuarios = home_path("Server/Credentials/toffu.bin");
    if !ruta_usuarios.exists() {
        writeLog("Error: No se encontró el archivo de usuarios. \n");
        exit(0);
    }
    let mut file = File::create(&ruta_usuarios).expect("Error al crear el archivo de usuarios");
    file.write_all(cadenaF.as_bytes()).expect("Error al escribir en el archivo de usuarios");
    writeLog("Usuarios actualizados correctamente. \n");
    //Ahora debemos actualizar la firma del IV con el nuevo hash de la llave AES
    let mut aesHash = Sha256::new();
    aesHash.update(aes_key_new);
    let aes_hash = aesHash.finalize();
    //Convertir el hash en base64
    let aes_hash_base64 = base64::encode(aes_hash);
    //Ahora debemos modificar la firma del IV en el archivo de firma del IV
    let ruta_firma_iv = home_path("Server/Credentials/presentacion2Sign.pp");
    if !ruta_firma_iv.exists() {
        writeLog("Error: No se encontró el archivo de firma del IV. \n");
        exit(0);
    }
    let mut file = File::create(&ruta_firma_iv).expect("Error al crear el archivo de firma del IV");
    file.write_all(aes_hash_base64.as_bytes()).expect("Error al escribir en el archivo de firma del IV");
    //Codigo para descifrar y despues cifrar el archivo mycooldaughter.yaml
    //Primer ubicamos el archivo 
    //let rutadougt = home_path("Server/myDaughter/mycooldaughter.yaml");
    //if !rutadougt.exists() {
    //    writeLog("Error: No se encontró el archivo de apis\n");
    //    exit(0);
    //}
    //let mut fileDaught = File::open(&rutadougt).expect("Error al abrir el archivo de usuarios");
    //let mut buffer2 = String::new();
    //fileDaught.read_to_string(&mut buffer2).expect("Error al leer el archivo de usuarios");
    ////Aqui comprobamos que si existe, entonces procedemos a descifrarlo con la llave y IV actuales
    //let mut cipher = openssl::symm::Crypter::new(
    //    openssl::symm::Cipher::aes_256_cbc(),
    //    openssl::symm::Mode::Decrypt,
    //    &aes_key_bytes,
    //    Some(&Iv),
    //).expect("Error al crear el descifrador AES");
    //let mut decrypted_role = vec![0; buffer2.len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
    //let mut count = cipher.update(&base64::decode(buffer2).expect("Error al decodificar el rol cifrado"), &mut decrypted_role).expect("Error al descifrar el rol");
    //count += cipher.finalize(&mut decrypted_role[count..]).expect("Error al finalizar el descifrado");
    //decrypted_role.truncate(count);
    //let decrypted_role_string = String::from_utf8(decrypted_role).expect("Error al convertir el rol descifrado a String");
    ////Aqui ya tenemos todo descifrado en decrypted_role_string asi que procedemos a cifrarlo 
    //let mut cipher = openssl::symm::Crypter::new(
    //    openssl::symm::Cipher::aes_256_cbc(),
    //    openssl::symm::Mode::Encrypt,
    //    &aes_key_new,
    //    Some(&Iv),
    //).expect("Error al crear el cifrador AES");
    //let mut encrypted_role = vec![0; decrypted_role_string.len() + openssl::symm::Cipher::aes_256_cbc().block_size()];
    //let mut count = cipher.update(decrypted_role_string.as_bytes(), &mut encrypted_role).expect("Error al cifrar el rol");
    //count += cipher.finalize(&mut encrypted_role[count..]).expect("Error al finalizar el cifrado");
    //encrypted_role.truncate(count);
    ////Convertimos el rol cifrado a base64
    //let encrypted_role_base64 = base64::encode(&encrypted_role);
    ////Ahora escribirmos un nuevo archivo con este contenido
    //let mut file = File::create(&rutadougt).expect("Error al crear el archivo de firma del IV");
    //file.write_all(encrypted_role_base64.as_bytes()).expect("Error al escribir en el archivo de firma del IV");
    writeLog("Firma del IV actualizada correctamente. \n");

}
fn rotRSA(){
    //Rotar las llaves publica y privada del servidor
    //Aqui vamos a generar nuevas llaves RSA
    let output = std::process::Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(home_path("Server/Credentials/private_key.pem"))
        .arg("2048")
        .output()
        .expect("Error al ejecutar openssl para generar la llave privada");
    if output.status.success() {
        writeLog("Llave privada del servidor rotada correctamente. \n");
    } else {
        writeLog(&format!("Error al rotar la llave privada del servidor: {} \n", String::from_utf8_lossy(&output.stderr)));
    }
    //Ahora, apartir de la llave privada generada, vamos a generar una nueva llave publica
    let output = std::process::Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(home_path("Server/Credentials/private_key.pem"))
        .arg("-pubout")
        .arg("-out")
        .arg(home_path("Server/Credentials/public_key.pem"))
        .output()
        .expect("Error al ejecutar openssl para generar la llave pública");
    if output.status.success() {
        writeLog("Llave pública del servidor rotada correctamente. \n");
    } else {
        writeLog(&format!("Error al rotar la llave pública del servidor: {} \n", String::from_utf8_lossy(&output.stderr)));
    }
    //Llaves rsa rotadas correctamente
}
fn verifyIv() -> bool{
    //Aquí vamos a checar las firmas de los archivos del servidor (las tres llaves y el IV)
    let ruta_firma_iv = home_path("Server/Credentials/presentacion1Sign.pp");
    if !ruta_firma_iv.exists() {
        writeLog("Error: No se encontró el archivo de firma del IV. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_firma_iv).expect("Error al abrir el archivo de firma del IV");
    let mut ivBuffer = String::new();
    file.read_to_string(&mut ivBuffer).expect("Error al leer el archivo de firma del IV");
    //abrimos el archivo del IV
    let ruta_iv = home_path("Server/IVGenServer/presentacion1.pptx");
    if !ruta_iv.exists(){
        writeLog("Error: No se encontró el archivo de IV. \n");
        exit(0);
    }
    let mut iv_file = File::open(&ruta_iv).expect("Error al abrir el archivo de IV");
    let mut iv_buffer = String::new();
    iv_file.read_to_string(&mut iv_buffer).expect("Error al leer el archivo de IV");
    //Ahora debemos hashear el IV
    let mut iv_hash = Sha256::new();
    let decodeivbuffer = base64::decode(iv_buffer).expect("Error al decodificar el IV");
    iv_hash.update(&decodeivbuffer);
    let iv_hash_result = iv_hash.finalize();
    //Convertir el hash a base64
    let iv_hash_base64 = base64::encode(iv_hash_result);
    
    if ivBuffer == iv_hash_base64 {
        writeLog("Iv verificada sin cambios ni alteraciones. \n");
        true
    }else{
        writeLog("Iv alterada o modificada, se recomienda restaurar el servidor. \n");
        false
    }
}
fn verificarLlavesRSA() -> bool{
    //Abrir archivo de la llave privada
    let ruta_private_key = home_path("Server/Credentials/private_key.pem");
    let mut privexists = false;
    if !ruta_private_key.exists() {
        writeLog("Error: No se encontró el archivo de llave privada. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_private_key).expect("Error al abrir el archivo de llave privada");
    let mut private_key_buffer = String::new();
    file.read_to_string(&mut private_key_buffer).expect("Error al leer el archivo de llave privada");
    //Verificar que la llave privada sea valida
    let private_key = openssl::rsa::Rsa::private_key_from_pem(private_key_buffer.as_bytes());
    match private_key {
        Ok(_) => {
            writeLog("Llave privada verificada correctamente. \n");
            privexists = true;
        },
        Err(e) => {
            writeLog(&format!("Error al verificar la llave privada: {} \n", e));
            exit(0);
        }
    }
    //Ahora verificamos la llave publica
    let mut pubexists = false;
    let ruta_public_key = home_path("Server/Credentials/public_key.pem");
    if !ruta_public_key.exists() {
        writeLog("Error: No se encontró el archivo de llave pública. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_public_key).expect("Error al abrir el archivo de llave pública");
    let mut public_key_buffer = String::new();
    file.read_to_string(&mut public_key_buffer).expect("Error al leer el archivo de llave pública");
    //Verificar que la llave publica sea valida
    let public_key = openssl::rsa::Rsa::public_key_from_pem(public_key_buffer.as_bytes());
    match public_key {
        Ok(_) => {
            writeLog("Llave pública verificada correctamente. \n");
            pubexists = true;
        },
        Err(e) => {
            writeLog(&format!("Error al verificar la llave pública: {} \n", e));
            exit(0);
        }
    }
    return (privexists && pubexists);
}
fn verifyaesKey() -> bool{
    //Abrir el archivo de la llave AES
    let ruta_aes = home_path("Server/AESKeyServer/presentacion2.pptx");
    if !ruta_aes.exists() {
        writeLog("Error: No se encontró el archivo de llave AES. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_aes).expect("Error al abrir el archivo de llave AES");
    let mut aes_keyStr = String::new();
    file.read_to_string(&mut aes_keyStr).expect("Error al leer el archivo de la llave AES");
    //Ahora a abrir el archivo de la firma de la llave AES
    let ruta_firma_aes = home_path("Server/Credentials/presentacion2Sign.pp");
    if !ruta_firma_aes.exists() {
        writeLog("Error: No se encontró el archivo de firma de la llave AES. \n");
        exit(0);
    }
    let mut file = File::open(&ruta_firma_aes).expect("Error al abrir el archivo de la firma de la llave AES");
    let mut firma_aes_buffer = String::new();
    file.read_to_string(&mut firma_aes_buffer).expect("Error al leer el archivo de la firma de la llave AES");
    //Hasheando llave aes:
    let mut hasheadoraes = Sha256::new();
    let llaveAesStr1 = base64::decode(aes_keyStr).expect("Error al decodificar la llave AES");
    hasheadoraes.update(llaveAesStr1);
    let aes_hash = hasheadoraes.finalize();
    //Convertir el hash a base64
    let aes_hash_base64 = base64::encode(aes_hash);
    if aes_hash_base64 == firma_aes_buffer {
        writeLog("Llave AES verificada correctamente. \n");
        true
    } else {
        writeLog("Llave AES alterada o modificada, se recomienda restaurar el servidor. \n");
        false
    }
}
//Funcion para exportar a .zip dos carpetas
fn export_zip1() -> zip::result::ZipResult<()> {
    let folders = vec![home_path("Server"), home_path("Sofia")];
    let zip_file = File::create("Server.zip")?;
    let mut zip = ZipWriter::new(zip_file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);

    for folder in folders {
        let path = Path::new(&folder);
        let walkdir = WalkDir::new(path);

        for entry in walkdir.into_iter().filter_map(Result::ok) {
            let path = entry.path();
            let name = path.strip_prefix(&folder).unwrap();

            if path.is_file() {
                let mut f = File::open(path)?;
                let mut buffer = Vec::new();
                f.read_to_end(&mut buffer)?;

                let full_name = Path::new(&folder)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                let full_path = PathBuf::from(full_name).join(name);

                zip.start_file(full_path.to_string_lossy(), options)?;
                zip.write_all(&buffer)?;
            } else if name.as_os_str().len() != 0 {
                let full_name = Path::new(&folder)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                let full_path = PathBuf::from(full_name).join(name).to_string_lossy().to_string() + "/";
                zip.add_directory(full_path, options)?;
            }
        }
    }

    zip.finish()?;
    Ok(())
}
fn importZip1(direccion_destino: &str) -> zip::result::ZipResult<()> {
    // Abrimos el archivo ZIP
    let zip_file = File::open(direccion_destino)?;
    let mut archive = ZipArchive::new(zip_file)?;

    // Iteramos sobre cada archivo dentro del ZIP
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let home_dir = dirs::home_dir().expect("No se pudo obtener el directorio home");
        let outpath = Path::new(&home_dir).join(file.name());

        // Creamos los directorios si no existen
        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Opcional: poner permisos unix si el archivo comprimido los tenía
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}
//Funcion para procesar comandos
fn command_reader(command: String, mut usuario: savedUser){
    //Primero debemos dividir el comando por espacios
    let mut comm = command.trim().split(" ").collect::<Vec<&str>>();
    let mut seckey = false;
    if comm[0] == "seckey" && comm.len() == 2 && usuario.role == 'A' {
        if comm[1] == "offprod"{
            let ruta_logo = home_path("Server/Credentials/logo.svg");
            if !ruta_logo.exists() {
                writeLog("Error: No se encontró el archivo logo.svg. \n");
                return;
            }
            //Si el archivo existe, debemos cambiar su contenido a PROD=false
            let mut file = File::create(&ruta_logo).expect("Error al crear el archivo logo.svg");
            file.write_all(b"PROD=false").expect("Error al escribir en el archivo logo.svg");
            writeLog("Servidor en modo mantenimiento\n");     
        }else if comm[1] == "onprod" {
            let ruta_logo = home_path("Server/Credentials/logo.svg");
            if !ruta_logo.exists() {
                writeLog("Error: No se encontró el archivo logo.svg. \n");
                return;
            }
            //Si el archivo existe, debemos cambiar su contenido a PROD=true
            let mut file = File::create(&ruta_logo).expect("Error al crear el archivo logo.svg");
            file.write_all(b"PROD=true").expect("Error al escribir en el archivo logo.svg");
            writeLog("Servidor en modo producción\n");
            
        }else if comm[1] == "verify" {
            let verificarIv = verifyIv();
            let verifivarRSA = verificarLlavesRSA();
            let verificarAes = verifyaesKey();
            if verificarIv && verifivarRSA && verificarAes {
                writeLog("Servidor verificado correctamente. \n");
            } else if usuario.role == 'A' {
                writeLog("Servidor no verificado, se recomienda restaurar el servidor. Desea restaurar el servidor (s/n): \n");
                let mut restore = String::new();
                io::stdin().read_line(&mut restore).expect("Error al leer la respuesta");
                restore = restore.trim().to_string();
                if restore.to_lowercase() == "s" {
                    writeLog("Restaurando servidor...\n");
                    create_admin_server();
                }
            }
        }
    }else if comm[0] == "seckey" && comm.len() == 4 && usuario.role == 'A' {
        if comm[1] == "rot"{
            if comm[2] == "server" {
                if comm[3] == "asymetric"{
                    rotRSA();
                    
                }else if comm[3] == "iv" {
                    rotIV();
                    
                }else if comm[3] == "aes" {
                    rotaes();
                    
                }else if( comm[3] == "ALL"){
                    rotIV();
                    rotaes();
                    rotRSA();
                }
            }
        }
    }else if comm[0] == "export" && comm.len() == 1 && (usuario.role == 'A' || usuario.role == 'U') {
        //Exportar la configuracion del servidor a un .zip
        export_zip1();
        writeLog(format!("Exportacion hecha por {}", &usuario.username.clone()).as_str());
    }else if comm[0] == "import" && comm.len() ==2 && (usuario.role == 'A' || usuario.role == 'U') {
        //Importar la configuracion desde la direccion escrita por el usuario
        importZip1(comm[1]);
        writeLog(format!("Importacion hecha por {} desde {}", &usuario.username.clone(), comm[1]).as_str());
    }else if comm[0] == "user" && comm[1] == "create" && (usuario.role == 'A' || usuario.role=='U'){
        usuario = create_user(true);
    }else if comm[0] == "user" && comm[1] == "login" {
        usuario = login_user();
    }else if comm[0] == "user" && comm[1] == "changepassword" {
        //Cambiarle la contraseña a un usuario requerira seguir los siguientes pasos:
        /*
            1. Conseguir la lista de usuarios
            2. Verificar cual es el usuario en la lista
            3. cambiar el segundo espacio de ese usuario, ya que ese es la contraseña
                - Esto solo si el usuario logra saber cual es su contraseña actual
        */
        let pathUsuarios = home_path("Server/Credentials/toffu.bin");
        if (!pathUsuarios.exists()) {
            writeLog("Archivo inexistente");
            exit(0);
        }
        //Aquí vamos a abrir el archivo
        let mut file = File::open(&pathUsuarios).expect("Error al abrir el archivo de usuarios");
        let mut contenido = String::new();
        file.read_to_string(&mut contenido).expect("Error al colocar el contenido");
        //println!("{}", contenido)
        //Ahora debemos separar a los usuarios por ¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢
        let usuarios: Vec<&str> = contenido.split("¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢").collect();
        //A veces hay basura, hay que quitarla
        let mut usuarios_limpios: Vec<&str> = Vec::new();
        for usuario in usuarios {
            if !usuario.trim().is_empty() {
                usuarios_limpios.push(usuario.trim());
            } 
        }
        //Ahora debemos recorrer esta lista para poder separar cada elemento por \n
        let mut nuevoUsuarios: Vec<Vec<String>> = Vec::new();
        for usuario in usuarios_limpios {
            let mut nuevosacom : Vec<String> = Vec::new();
            let bruto: Vec<&str>= usuario.split("\n").collect();
            nuevosacom = vec![bruto[0].to_string(), bruto[1].to_string(), bruto[2].to_string(), bruto[3].to_string()];
            nuevoUsuarios.push(nuevosacom);
        }
        let mut hasher2 = Sha256::new();
        let saltayuda = usuario.salt.clone();
        let concatPassSalt = format!("{}{}", usuario.password, usuario.salt.clone());
        //println!("ConcatPassSalt: {}", concatPassSalt);
        hasher2.update(concatPassSalt.as_bytes());
        let resultadoHashPassword = hasher2.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let mut ih = 0;
        //Ahora debemos ir buscando el usuario correspondiente

        for mut usuario1 in nuevoUsuarios.clone() {

            if resultadoHashPassword == usuario1[1]{
                //Aqui pondremos lo que pasa cuando encuentre el usuario correspondiente
                //Pedir una contraseña nueva:
                let mut nuevapass1 = String::new();
                println!("Escriba la nueva password: ");
                nuevapass1 = read_password().expect("Error al leer la nueva password");
                //io::stdin().read_line(&mut nuevapass1).expect("Error al leer la linea"); //Aqui pido la contraseña
                if nuevapass1 == "exit" {
                    break;
                }
                let mut nuevapass2 = String::new();
                println!("Repetir la contraseña: ");
                nuevapass2 = read_password().expect("Error al leer la repeticion de la nueva password");
                //io::stdin().read_line(&mut nuevapass2).expect("Error al leer la repeticion de la contraseña"); //La vuelvo a pedir
                if nuevapass2 == "exit" {
                    break;
                }
                if nuevapass1 == nuevapass2 && (nuevapass1 != "exit" && nuevapass2 != "exit") {
                    usuario.password = nuevapass1.clone();
                    //Ahora debemos cambiar la contraseña aqui
                    //let semilla = format!("{}{}", nuevapass1, saltayuda);
                    let mut hasher2 = Sha256::new();
                    let concatPassSalt = format!("{}{}", nuevapass1, usuario.salt);
                    //println!("ConcatPassSalt: {}", concatPassSalt);
                    hasher2.update(concatPassSalt.as_bytes());
                    let nuevapass3 = hasher2.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    //let nuevapass4 = base64::encode(nuevapass3);
                    nuevoUsuarios[ih][1] = nuevapass3.clone();
                }

            }
            ih += 1;
        }
        //Ahora debemos hacer la cadena que se pondra en el archivo:
        let mut stringfinal = String::new();
        for usuario1 in nuevoUsuarios {
            let userrr = format!("{}\n{}\n{}\n{}\n¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢\n", usuario1[0], usuario1[1], usuario1[2], usuario1[3]);
            stringfinal.push_str(&userrr.as_str());
        }
        //Ahora a sobreescribir el archivo
        let mut file = File::create(&pathUsuarios).expect("Error al crear el archivo de usuarios");
        file.write_all(stringfinal.as_bytes()).expect("Error al escribir en el archivo de usuarios");
        writeLog("contraseña actualizada correctamente. \n");
    }else if comm[0] == "user" && comm[1] == "delete" && usuario.role == 'A' {
        //Funcion para borrar un usuario
        /*
            1. Abrir el archivo de usuarios
            2. Verificar cual es este usuario
            3. Verificar que el archivo tenga mas de un usuario A (el primero del archivo no debe ser borrado)
        */
        let pathUsuarios = home_path("Server/Credentials/toffu.bin");
        let mut buffer = String::new();
        let mut file = File::open(&pathUsuarios).expect("Error al abrir el archivo");
        file.read_to_string(&mut buffer).expect("Error al obtener los datos");
        let usuarios1 : Vec<&str>= buffer.split("\n¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢\n").collect();
        let mut usuariosLimpios : Vec<Vec<String>> = Vec::new();
        for i in usuarios1 {
            let usuarioh: Vec<&str>= i.split("\n").collect();
            if usuarioh != vec![""] {
                let mut usuarioh2 : Vec<String> = Vec::new();
                usuarioh2.push(usuarioh[0].to_string());
                usuarioh2.push(usuarioh[1].to_string());
                usuarioh2.push(usuarioh[2].to_string());
                usuarioh2.push(usuarioh[3].to_string());
                usuariosLimpios.push(usuarioh2);
            }
            
        }
        let mut usuarioE = String::new();
        let mut passE = String::new();
        writeLog("Dame el usuario a eliminar: \n");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut usuarioE).expect("Error al leer el nombre");
        let usuarioE = usuarioE.trim();
        writeLog("Password\n");
        passE = read_password().expect("Error al leer password");
        let mut ih = 0;
        for usuariocool in usuariosLimpios.clone() {
            let mut hasher2 = Sha256::new();
            hasher2.update(format!("{}{}", usuarioE, usuariocool[3]).as_bytes());
            let hashuser = hasher2.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
            //Hashing de password
            let mut hasher3333333  = Sha256::new();
            hasher3333333.update(format!("{}{}", passE, usuariocool[3]));
            let hashPass = hasher3333333.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();
            
            if hashuser == usuariocool[0] && hashPass == usuariocool[1] {
                usuariosLimpios.remove(ih);
                writeLog(format!("Se ha borrado el usuario {}", ih).as_str());
            }
            ih += 1;
        }
        //Aqui se crea la cadena para insertar en el texto final del usuario
        let mut cadenaF: String = String::new();
        for i in usuariosLimpios {
            let cadena1 = format!("{}\n{}\n{}\n{}\n¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢¢\n", i[0], i[1], i[2], i[3]);
            cadenaF.push_str(cadena1.clone().as_str());
        }
        let mut file = File::create(&pathUsuarios).expect("Error al sobreescribir el archivo");
        file.write_all(cadenaF.as_bytes()).expect("Error al escribir el archivo");
        writeLog("Archivo sobreescrito exitosamente\nUsuario eliminado del sistema.\n");
        
    }else if comm[0] == "logs" && comm[1] == "read" {
        //Leer todos los logs en la carpeta logs de aqui
        let pathlogs = Path::new("src/logs");
        let mut archivos_logs: Vec<String> = Vec::new();
        let mut buffer: String = String::new();
        //Aqui debemos leer estos archivos con un maximo de 5 archivos
        writeLog("Dia del log Y-M-D: \n");
        io::stdin().read_line(&mut buffer).expect("Error al leer la linea");
        buffer = buffer.trim().to_string();
        if pathlogs.is_dir() {
            for entry_result in fs::read_dir(pathlogs).expect("No se pudo leer el directorio") {
                if let Ok(entry) = entry_result {
                    let path = entry.path();
                    //let fecha = String::from(&path.to_str());
                    
                    if path.extension() == Some(OsStr::new("log")){
                        
                        if let Some(nombre_archivo) = path.file_name().and_then(|n| n.to_str()) {
                            // Comparar prefijo exacto: fecha_ (por ejemplo "2025-07-23_")
                            //println!("{:?}", buffer);
                            if nombre_archivo.starts_with(&format!("{}_", buffer)){
                                //println!("{:?}", path);
                                archivos_logs.push(nombre_archivo.to_string());
                            }
                            //if nombre_archivo.starts_with(&format!("{}_", fecha)) {
                            //    archivos_logs.push(path);
                            //}
                        }
                    }

                }
            }
        } else {
            println!("La ruta no es un directorio");
        }
        archivos_logs.sort();
        for i in archivos_logs {
            let titulo = i.as_str();
            writeLog(format!("Archivo a leer: {}", titulo).as_str());
            let direccion = format!("src/logs/{}", i);
            let mut contenido = String::new();
            let mut file = File::open(direccion).expect("Error al obtener el contenido");
            file.read_to_string(&mut contenido).expect("Error al obtener contenido");
            println!("\n¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬|\n{}\n¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬|\n", contenido);
            writeLog(format!("Archivo log {} abierto y leido", titulo).as_str());
        }
    }else if comm[0] == "uploadImage" && comm.len()==2 && (usuario.role=='A' || usuario.role == 'B') {
        //Aqui debemos subir alguna imagen 
        let origen = Path::new(comm[1]);
        let destino = home_path("Sofia/Images/imagenDefault.jpg");
        if !origen.exists() {
            writeLog("Error, la direccion origen no existe");
            exit(0);
        }
        if !destino.exists() {
            writeLog("Error, la direccion destino no existe");
            exit(0);
        }
        let mut imagenN = File::open(origen).expect("Error, imagen inexistente");
        let mut contenido = Vec::new();
        imagenN.read_to_end(&mut contenido).expect("Error al tomar el contenido");
        //Ahora debemos escribir una imagen nueva llamada imagenDefault.jpg
        let mut nFile = File::create(destino).expect("No se pudo crear el archivo");
        nFile.write_all(&contenido).expect("Error al tratar de crear una imagen nueva");
        writeLog("Imagen Rotada");
        //Vamos a crear una nueva imagen mezclada
        let frase = createPhrase();
        let miImagen = base64::encode(contenido);
        let mut rng = rand::thread_rng();
        let mut numero = rng.gen_range(0..=miImagen.len() - 1); 
        let mut hasheadorcool = Sha512::new();
        let frase = format!("{}{}", numero, miImagen);
        hasheadorcool.update(frase.as_bytes());
        let fFinal = hasheadorcool.finish();
        let ffFInal = base64::encode(fFinal);
        let mezclaCool = mixImagePhrase(miImagen, ffFInal);
        
        let ruta_imagen_mezclada = home_path("Server/Credentials/Patricia.love");
        let mut file = File::create(&ruta_imagen_mezclada).expect("Error al crear el archivo de imagen mezclada");
        file.write_all(mezclaCool.as_bytes()).expect("Error al escribir la imagen mezclada");
        writeLog("Imagen mezclada creada y guardada correctamente. \n");
    }else if comm[0] == "exit" {
        writeLog(format!("{} ha salido del servidor y cerrado el programa\n", &usuario.username).as_str());
        exit(0);
    }else if comm[0] == "api" && comm.len() == 3 && usuario.role == 'A'{
        if comm[1] == "register" {
            //Codigo para poder registrar una API con su respectiva llave publica y privada
            //Esta se cifrará con la llave AES del servidor
            let private_output = Command::new("openssl")
                .args(&["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
                .output()
                .expect("Fallo al generar la clave privada");
            let private_key = String::from_utf8(private_output.stdout)
                .expect("Error al convertir la clave privada a UTF-8");

            let mut child = Command::new("openssl")
                .args(&["rsa", "-pubout"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("Fallo al ejecutar openssl para clave pública");
                
            // Escribimos la clave privada en la entrada estándar del proceso
            {
                let stdin = child.stdin.as_mut().expect("No se pudo abrir stdin");
                stdin
                    .write_all(private_key.as_bytes())
                    .expect("No se pudo escribir en stdin");
            }
        
            // Capturar la salida (clave pública)
            let output = child.wait_with_output().expect("Fallo al capturar la salida");
            let public_key = String::from_utf8(output.stdout)
                .expect("Error al convertir la clave pública a UTF-8");
            

            //Ahora debemos unirlas y concatenarlas
            let mut rng = rand::thread_rng();
            let numero_aleatorio = rng.gen_range(1000..9999);
            let mut hasheador4000 = Sha512::new();
            hasheador4000.update(numero_aleatorio.to_string().as_bytes());
            let saltTemp = hasheador4000.finish();
            let mezcla = format!("{}{}{}", private_key, public_key, base64::encode(saltTemp));
            let mut hasheador4001 = Sha512::new();
            hasheador4001.update(mezcla.as_bytes());
            let salta = hasheador4001.finish();
            let saltF = base64::encode(salta);
            let mut hasheador4002 = Sha512::new();
            hasheador4002.update(format!("{}{}", comm[2], saltF).as_bytes());
            let hashNombre = hex::encode(hasheador4002.finish()); 

            // Mostrar claves
            //println!("🔐 Clave privada RSA:\n{}", private_key);
            println!("📢 Clave pública RSA:\n{}", public_key);
            //println!("Salt de api: {}", saltF);
            //Ahora es hora de crear el string definitivo:
            let stringA = format!("{}\n{}\n\n", hashNombre, saltF);
            //let stringAA = hex::encode(stringA);
            //Ahora a colocar todo esto en sus respectivos archivos
            let archivoPrivado = home_path(format!("Server/myDaughter/{}.key", hashNombre).as_str());
            let archivoPublico = home_path(format!("Server/myDaughter/{}.pem", hashNombre).as_str());
            let archivoSaltNombre = home_path("Server/myDaughter/mycooldaughter.yaml");
            //println!("{:?}", archivoPrivado);
            let mut archivo = File::create(&archivoPrivado).expect("Error al crear el archivo .key");
            archivo.write_all(private_key.as_bytes()).expect("Error al escribir en el archivo .key");
            let mut archivo = File::create(&archivoPublico).expect("Error al crear el archivo .pem");            
            archivo.write_all(public_key.as_bytes()).expect("Error al escribir en el archivo .pem");
            //Leer el archivo antes de escribir sobre el:
            let mut archivo = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&archivoSaltNombre)
                .expect("Error al abrir archivo para añadir contenido");
            archivo.write_all(stringA.as_bytes()).expect("Error al agregar contenido al archivo .yaml -> ");
            let archivoNombres = home_path("Server/myDaughter/thenamesmotherfucker.kissmyass");
            let mut archivoNames = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&archivoNombres)
            .expect("Error al abrir el archivo de nombres");
            archivoNames.write_all(format!("{}\n", comm[2]).as_bytes()).expect("Error al agregar informacion al archivo de nombres");
            writeLog(format!("Llaves para la nueva API '{}' creadas\n", comm[2]).as_str());

        }else if comm[1] == "delete" {
            //Primero necesitamos extraer la lista de salts + nombres hasheados que hay en el .yaml
            let rutacosas = home_path("Server/myDaughter/mycooldaughter.yaml");
            if !rutacosas.exists() {
                writeLog("El servidor a sido comprometodo\nSe requiere reseteo URGENTEMENTE!!!\nLlamen a Dios!!!\n");
                exit(0);
            }
            let mut buffer = String::new();
            let mut archivo = File::open(&rutacosas).expect("Error al abrir el archivo de yaml");
            archivo.read_to_string(&mut buffer).expect("Error al extraer la data del archivo yaml");
            let mut pares :Vec<&str>= buffer.split("\n\n").collect();
            if pares[pares.len() - 1] == "" {
                pares.pop();
            }
            //pares.pop();
            let mut ih = 0;
            let mut banda = false;
            for par in pares.clone() {
                let mut parordenado: Vec<&str>= par.split("\n").collect();
                let semilla1 = format!("{}{}", comm[2], parordenado[1]);
                let mut hasheador4002 = Sha512::new();
                hasheador4002.update(semilla1.as_bytes());
                let hashearFinal = hasheador4002.finish();
                let hasherFinalHex = hex::encode(hashearFinal);
                if hasherFinalHex == parordenado[0] {
                    //Se encontró con el nombre hasheado, ahora debemos removerlo del par ordenado

                    //Borrando el archivo de las llaves
                    let llavePruv = home_path(format!("Server/myDaughter/{}.key", hasherFinalHex).as_str());
                    if llavePruv.exists() {
                        fs::remove_file(llavePruv).expect("Error al tratar de borrar el .key");
                    }
                    let llavePub = home_path(format!("Server/c/{}.pem", hasherFinalHex).as_str());
                    if llavePub.exists() {
                        fs::remove_file(llavePub).expect("Error al tratar de eliminar el archivo .pem");
                    }
                    pares.remove(ih);
                    banda = true;
                    //println!("{:?}", pares);
                    break;
                }ih+=1;
            }
            if banda {
                let mut stringA = String::new();
                for i in pares{
                    stringA = format!("{}{}\n\n", stringA, i);
                    //println!("{}", i);
                }
                let archivoyaml = home_path("Server/myDaughter/mycooldaughter.yaml");
                let mut archivo = File::create(archivoyaml).expect("Error al recrear el archivo");
                archivo.write_all(stringA.as_bytes()).expect("Error al cambiar el contenido del archivo .yaml");
                //println!("{}", stringA);
                writeLog("Api eliminada de la lista\n");
            }else {
                writeLog("No existe dicha api, lo siento\n");
            }
            
            //comm[2] nos dice el nombre, debemos verificar si ese nombre existe primero
        }
        

    }else {
        writeLog(format!("Error!!!\n Comando insexitente o son privilegios necesarios\nTuRol es {}\n", &usuario.role).as_str());
    }
}
fn admin_server() {
    let mut usuario = savedUser {
        username: String::new(),
        password: String::new(),
        role: '\0',
        salt: String::new()
    }; 
    //let frase: String = "".to_string();
    let rutaFirmap1 = home_path("Server/Credentials/presentacion1Sign.pp"); //iv
    let rutaFirmap2 = home_path("Server/Credentials/presentacion2Sign.pp"); //aes
    let ivGenServer = home_path("Server/IVGenServer/presentacion1.pptx");
    let AESkeyServer = home_path("Server/AESKeyServer/presentacion2.pptx");

    if rutaFirmap1.exists() && rutaFirmap2.exists() && ivGenServer.exists() && AESkeyServer.exists() {
        //Si ya existen los archivos iniciamos el proceso de login en el sistema
        usuario = login_user();
        println!("Todos los archivos existen. Ejecutando modo administrador...");

    } else {
        //Procesos 
        println!("Faltan archivos. Creando servidor de administración...");
        usuario = create_admin_server(); 
        
    }
    //Escribir un comando
    writeLog("Servidor de administración iniciado correctamente. \n");
    loop{
        let mut usuario1: savedUser = savedUser { username: usuario.username.clone(), password: usuario.password.clone(), role: usuario.role.clone(), salt: usuario.salt.clone()};
        writeLog("Ingrese un comando: \n");
        let mut command = String::new();
        io::stdin().read_line(&mut command).expect("Error al leer el programa");
        command = command.trim().to_string();
        command_reader(command, usuario1);
        //usuario.username = usuario1.username.clone();
        //usuario.password = usuario1.password.clone();
        //usuario.role = usuario1.role.clone();
        //usuario.salt = usuario1.salt.clone();
        //Para este punto, el servidor ya tiene los archivos necesarios para funcionar, ahora, al ser un servidor web, debemos hacer funciones acorde a lo que necesitamos
    }
}

fn main() {
    admin_server();
}
