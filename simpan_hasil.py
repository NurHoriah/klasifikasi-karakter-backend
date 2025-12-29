from database import get_db_connection
import json

def simpan_hasil(nama_siswa, data_input, tipe_karakter, akurasi):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Menyimpan data siswa jika belum ada
    cursor.execute('SELECT id FROM siswa WHERE nama = ?', (nama_siswa,))
    siswa = cursor.fetchone()
    if siswa is None:
        cursor.execute('INSERT INTO siswa (nama) VALUES (?)', (nama_siswa,))
        siswa_id = cursor.lastrowid
    else:
        siswa_id = siswa['id']

    # Menyimpan hasil klasifikasi
    cursor.execute('''
        INSERT INTO hasil_klasifikasi (siswa_id, tipe_karakter, akurasi)
        VALUES (?, ?, ?)
    ''', (siswa_id, tipe_karakter, akurasi))

    conn.commit()
    conn.close()
    print(f"✅ Hasil klasifikasi untuk {nama_siswa} telah disimpan.")
