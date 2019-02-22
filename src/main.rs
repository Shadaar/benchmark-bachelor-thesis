use pcap::{Capture, Direction};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    env,
    fs::File,
    io::prelude::*,
    path::Path,
    str,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn main() {
    let args: Vec<String> = env::args().collect();

    let size: usize = args[2].parse().unwrap();
    let iterate: u32 = args[3].parse().unwrap();

    //------------------- 
    let dest: [u8; 6] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
    let src: [u8; 6] = [0x00, 0x14, 0xfd, 0x1a, 0x60, 0x5e];
    let eth_type: [u8; 2] = [0x88, 0x70];
    let pcap_filter = "ether src 10:20:30:40:50:60";
    //-------------------

    println!("Using Interface {}", args[1]);
    println!("With {} bytes per packet", size);
    println!("-------------------------------");
    thread::sleep(Duration::from_secs(2));

    //Starting Test
    for iteration in 0..iterate {
        let (tx, rx) = mpsc::channel();
        let tx1 = mpsc::Sender::clone(&tx);

        let interface_name_1 = args[1].clone();
        let interface_name_2 = args[1].clone();
        let send_cap = Capture::from_device(&interface_name_2[..])
            .unwrap()
            .promisc(true)
            .snaplen(size as i32);
        let rec_cap = Capture::from_device(&interface_name_1[..])
            .unwrap()
            .promisc(true)
            .buffer_size(1_073_741_824)
            .snaplen(size as i32)
            .timeout(5000);
        //----------------------
        // Spawn Reciever Threat
        let reciever = thread::Builder::new()
            .name("Rec".to_string())
            .spawn(move || {
                let mut count_packets = 0;
                let mut counter = 0;
                let mut count_dam = 0;

                let mut cap = rec_cap.open().unwrap();
                cap.direction(Direction::In).unwrap();
                cap.filter(pcap_filter).unwrap();

                while let Ok(pak) = cap.next() {
                    let time = Instant::now();
                    if pak[..6] != src {
                        continue;
                    }
                    let data = match String::from_utf8(pak[14..30].to_vec()) {
                        Ok(x) => x,
                        Err(_) => {
                            count_dam += 1;
                            continue;
                        }
                    };

                    let id: Vec<&str> = data.split("::").collect();
                    if id.len() < 3 {
                        count_dam += 1;
                        continue;
                    }
                    if id[1] == "ENDEND" {
                        break;
                    } else {
                        match id[1].parse() {
                            Ok(n) => {
                                let pack = ("Reciever", n, time);
                                tx1.send(pack).unwrap();
                                count_packets += 1;
                                counter += pak.len();
                            }
                            Err(_e) => {
                                count_dam += 1;
                                continue;
                            }
                        };
                    }
                }

                let stat = cap.stats().unwrap();
                let packets = format!(
                    "Reciever: {:?}\nRecieved: {} packets / {} dameged ({} bytes)",
                    stat, count_packets, count_dam, counter
                );
                println!("{}", packets);
                packets
            })
            .unwrap();
        //----------------------

        // Spawn Sending  Threat
        let sender = thread::Builder::new()
            .name("Sender".to_string())
            .spawn(move || {
                let mut count_packets = 0;
                let mut counter = 0;

                let dummy = "abcdefgh".to_owned();
                let data = dummy.repeat(2000);

                let mut cap = send_cap.open().unwrap();
                cap.direction(Direction::Out).unwrap();

                let start = Instant::now();
                //while counter < 1_250_000_000 {
                while start.elapsed().as_secs() < 1 {
                    let message = format!("::{:06}::", count_packets);
                    let mut my_packet: Vec<u8> = Vec::with_capacity(size);
                    my_packet.extend_from_slice(&dest);
                    my_packet.extend_from_slice(&src);
                    my_packet.extend_from_slice( &eth_type);
                    my_packet.extend_from_slice( &message.as_bytes());
                    my_packet.extend_from_slice( &data.as_bytes()[..size - 24]);

                    let time = Instant::now();
                    cap.sendpacket( my_packet.as_slice()).expect("no Sending");

                    let pack = ("Sender", count_packets, time);
                    tx.send(pack).unwrap();
                    count_packets += 1;
                    counter += my_packet.len();
                }
                let end = start.elapsed();
                println!("{}.{:09} secs", end.as_secs(), end.subsec_nanos());
                thread::sleep(Duration::from_secs(1));
                // Tell reciever to stop
                let mut mess = String::from("::ENDEND::");
                mess.push_str(&data);
                let mut my_packet: Vec<u8> = Vec::with_capacity(64);
                my_packet.extend_from_slice(&dest);
                my_packet.extend_from_slice(&src);
                my_packet.extend_from_slice(&   eth_type);
                my_packet.extend_from_slice( mess.as_bytes());
                my_packet.extend_from_slice( &data.as_bytes()[..64 - 24]);
                cap.sendpacket(&my_packet[..64]).expect("no Sending");

                let stat = cap.stats().unwrap();
                let packets = format!(
                    "Sender: {:?}\nSend: {} packets({} bytes)",
                    stat, count_packets, counter
                );
                println!("{}", packets);
                packets
            })
            .unwrap();
        //----------------------
        // Main-Threat
        let send_str = sender.join().unwrap();
        let rec_str = reciever.join().unwrap();

        let mut send = BTreeMap::new();
        let mut rec = BTreeMap::new();

        for received in rx {
            match received.0 {
                "Sender" => {
                    send.insert(received.1, received.2);
                }
                "Reciever" => match rec.entry(received.1) {
                    Entry::Vacant(e) => {
                        e.insert(vec![received.2]);
                    }
                    Entry::Occupied(mut e) => {
                        e.get_mut().push(received.2);
                    }
                },
                _ => {}
            };
        }

        let mut output = "PacketNo.::Round-Trip Time:::AVG\n".to_owned();
        let mut total = 0;
        for send_p in send.iter() {
            match rec.get(send_p.0) {
                Some(rec_p) => {
                    let mut temp = format!("{:06}", send_p.0);
                    let mut sum = 0;
                    for rec_v in rec_p.iter() {
                        let mut temp_data = String::from("::");
                        let time = rec_v.duration_since(*send_p.1);
                        let timer = format!("{}{:09}", time.as_secs(), time.subsec_nanos());
                        temp_data.push_str(&timer);
                        let m: u64 = timer.parse().unwrap();
                        sum += m;
                        temp.push_str(&temp_data);
                    }
                    total += sum / rec_p.len() as u64;
                    let end = format!(":::{}\n", sum / rec_p.len() as u64);
                    temp.push_str(&end);
                    output.push_str(&temp);
                }
                None => {
                    let temp = format!("{:06}:: Packet lost\n", send_p.0);
                    output.push_str(&temp);
                }
            }
        }

        let path = format!("out/{:02}_logFile.txt", iteration);
        let path = Path::new(&path);
        let mut log_file = File::create(path).unwrap();
        log_file.write_all(&output.as_bytes()).unwrap();
        println!("-------------------------------");

        let avg = if rec.len() > 0 {
            format!("AVG Latency: {} ns\n", total / rec.len() as u64)
        } else {
            "AVG Latency: INFINITY\n".to_string()
        };
        let sp = format!("Send    : {} ({} bytes)\n", send.len(), send.len() * size);
        let rp = format!(
            "Unique Recieved: {} ({} bytes)\n",
            rec.len(),
            rec.len() * size
        );
        let ls = format!(
            "Lost    : {} ({:2.2}%)\n",
            send.len() - rec.len(),
            100.0 - (rec.len() as f64 / send.len() as f64) * 100.0
        );

        let mut meta = String::new();
        meta.push_str(&send_str);
        meta.push_str(&rec_str);
        meta.push_str("-------------------------------");
        meta.push_str(&avg);
        meta.push_str(&sp);
        meta.push_str(&rp);
        meta.push_str(&ls);

        let meta_path = format!("out/{:02}_metadata.txt", iteration);
        let meta_path = Path::new(&meta_path);
        let mut meta_file = File::create(meta_path).unwrap();
        meta_file.write_all(&meta.as_bytes()).unwrap();
    }
}

