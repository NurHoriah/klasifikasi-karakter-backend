# simpan_hasil.py
from db import get_collection
from datetime import datetime

def simpan_hasil(nama_siswa, data_input, tipe_karakter, akurasi):
    """
    Simpan hasil klasifikasi ke MongoDB Atlas
    """

    col = get_collection("hasil_klasifikasi")

    dokumen = {
        "nama_siswa": nama_siswa,
        "kelas": data_input.get("kelas"),
        "tipe_karakter": tipe_karakter,
        "akurasi": akurasi,

        # simpan SEMUA input (penting untuk CSV & Excel)
        "data_input": data_input,

        # timestamp (penting untuk filter tanggal)
        "created_at": datetime.utcnow()
    }

    col.insert_one(dokumen)

    print(f"✅ Hasil klasifikasi untuk {nama_siswa} tersimpan di MongoDB")
