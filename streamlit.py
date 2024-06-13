import streamlit as st
import pandas as pd
import pymongo
import altair as alt

# Konfigurasi koneksi MongoDB


client =  pymongo.MongoClient('mongodb://localhost:27017/')
db = client['latihan']
collection = db['bayu']

# Mengambil data dari MongoDB
data = pd.DataFrame(list(collection.find()))

# Membersihkan data jika diperlukan
data['timestamp'] = pd.to_datetime(data['timestamp'])
data['day'] = data['timestamp'].dt.day
data['month'] = data['timestamp'].dt.month
data['year'] = data['timestamp'].dt.year

# Menghitung jumlah penggunaan APD dan tidak penggunaan APD
usage_count = data['class'].value_counts().reset_index()
usage_count.columns = ['class', 'count']

# Visualisasi penggunaan APD
chart_apd = alt.Chart(usage_count).mark_bar().encode(
    x='class',
    y='count',
    color='class'
).properties(
    title='Penggunaan APD'
)

# Visualisasi data berdasarkan hari
day_count = data.groupby(['day', 'class']).size().reset_index(name='count')
chart_day = alt.Chart(day_count).mark_bar().encode(
    x='day:O',
    y='count:Q',
    color='class:N',
    column='class:N'
).properties(
    title='Distribusi Penggunaan APD Berdasarkan Hari'
)

# Visualisasi data berdasarkan bulan
month_count = data.groupby(['month', 'class']).size().reset_index(name='count')
chart_month = alt.Chart(month_count).mark_bar().encode(
    x='month:O',
    y='count:Q',
    color='class:N',
    column='class:N'
).properties(
    title='Distribusi Penggunaan APD Berdasarkan Bulan'
)

# Visualisasi data berdasarkan tahun
year_count = data.groupby(['year', 'class']).size().reset_index(name='count')
chart_year = alt.Chart(year_count).mark_bar().encode(
    x='year:O',
    y='count:Q',
    color='class:N',
    column='class:N'
).properties(
    title='Distribusi Penggunaan APD Berdasarkan Tahun'
)

# Menampilkan visualisasi di Streamlit
st.title('Visualisasi Penggunaan APD')

st.altair_chart(chart_apd, use_container_width=True)
st.altair_chart(chart_day, use_container_width=True)
st.altair_chart(chart_month, use_container_width=True)
st.altair_chart(chart_year, use_container_width=True)