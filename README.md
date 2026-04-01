# Infosys_Springboard_PolicyNav_Public-_Policy_Navigation_Using_AI
# 🧠 PolicyNav
AI-Powered Policy Document Analysis & Navigation System  
Transforming complex policy documents into actionable insights using AI.
##Quick Links

| Category          | Link                                 |
| ----------------- | ------------------------------------ |
| 📽️ Demo Video    | [Video Link](https://drive.google.com/file/d/1mbPmmrhLD5Z8etwEr7z8v-OQ9IUnaCUi/view?usp=sharing)                         |
| 🧩 Source Code    | This Repository                      |
| 🧠 AI Models      | Qwen · Sentence Transformers · FAISS · NLLB|

## 📌 Table of Contents

- About the Project  
- Problem Statement & Motivation  
- Key Features  
- Architecture  
- Tech Stack  
- Models Used  
- Project Structure  
- Installation & Setup  
- Usage Guide  
- Admin Controls  
- Datasets & Evaluation  
- Screenshots  
- Roadmap  
- Team  
- License  



## 📖 About the Project

**PolicyNav** is an AI-powered system designed to simplify the exploration and understanding of complex policy documents using modern NLP techniques and Retrieval-Augmented Generation (RAG).

It enables users to:
- Search across large document collections intelligently  
- Generate contextual answers using AI  
- Visualize relationships via knowledge graphs  
- Summarize lengthy documents  
- Analyze readability of content  

📌 Built as part of **Infosys Springboard Internship Final Project**  
📌 Target users: Common persons, Researchers, policy analysts, students, government professionals  



## 🎯 Problem Statement & Motivation

## 📄 Problem & Solution

**Problem:**  
Public policy documents are often lengthy, complex, and difficult to understand due to technical language, making it challenging for users to quickly find relevant information. There is a lack of intelligent systems that enable easy search, summarization, and question-answering over such documents. This results in poor accessibility, time-consuming analysis, and potential misinterpretation of policies.

**Solution:**  
Our AI-powered system helps to:
- Extract meaningful insights instantly  
- Enable semantic search across documents  
- Visualize relationships between entities  
- Simplify and summarize complex content



## 🚀 Key Features

## 👤 User Features

- 🔐 **Secure Authentication** – JWT-based login & registration  
- 🔎 **RAG Search** – AI-powered semantic search using FAISS  
- 📊 **Readability Analyzer** – Flesch, Gunning Fog, and SMOG metrics  
- 🧠 **Document Summarization** – Transformer-based summarization  
- 🌐 **Knowledge Graph** – Entity relationship visualization  
- 🕘 **Query History** – Track previous searches & outputs  
- 📈 **Dashboard** – Interactive analytics & insights  

## 🌐 Multilingual Support

PolicyNav uses Facebook's **NLLB-200** (No Language Left Behind) model for high-quality, bi-directional translation. Your question is first translated to English for FAISS search, then the AI answer is translated back to your chosen language.

| **Language** | **NLLB-200 Code** |
|---|---|
| English | `eng_Latn` |
| Hindi | `hin_Deva` |
| Tamil | `tam_Taml` |
| Telugu | `tel_Telu` |
| Kannada | `kan_Knda` |
| Marathi | `mar_Deva` |
| Bengali | `ben_Beng` |


### 🛠 Admin-only Features

- Secure admin access  
- Upload and manage policy documents  
- Monitor system usage  
- View user activity and search logs  
- Manage document indexing and vector store  



## 🧩 Architecture

Monolithic AI system integrating NLP pipelines, vector search, and visualization tools.
## 🧩 Architecture Diagram

<p align="center">
  <img src="images/architecture.png" width="900"/>
  <br/>
  <em>Figure: End-to-end system architecture of PolicyNav</em>
</p>



## 🗄 Database Schema

<p align="center">
  <img src="images/database_schema.png" width="900"/>
  <br/>
  <em>Figure: Entity Relationship Diagram (ERD) of the system database</em>
</p>



## 🛠 Tech Stack

- 🎨 **Frontend:** Streamlit  
- ⚙️ **Backend:** Python  
- 🤖 **NLP Models:** Hugging Face Transformers  
- 🔍 **Vector Search:** FAISS  
- 🗄️ **Database:** SQLite  
- 🔐 **Security:** JWT, bcrypt  
- 📊 **Visualization:** Plotly, PyVis  
- 🧠 **NLP:** spaCy  


## 🤖 Models Used

| Model / Tool                   | Purpose                                  | Framework       |
| ------------------------------ | ---------------------------------------- | --------------- |
| Sentence Transformers          | Text embeddings for semantic search      | 🤗 Transformers |
| FAISS                          | Vector similarity search (RAG retrieval) | Facebook AI     |
| Qwen2.5                        | Answer generation (LLM)                  | Transformers    |
| spaCy                          | Named Entity Recognition                 | spaCy           |
| TextStat                       | Readability scoring                      | Python          |
| NLLB (No Language Left Behind) | Multilingual text translation            | 🤗 Transformers |


| Model / Tool                   | One-line Description                                                                            |
| ------------------------------ | ----------------------------------------------------------------------------------------------- |
| Sentence Transformers          | Converts text into dense vector embeddings for semantic understanding                           |
| FAISS                          | Performs fast similarity search on vector embeddings for retrieval                              |
| Qwen2.5                        | Generates context-aware answers using large language modeling                                   |
| spaCy                          | Extracts named entities and linguistic features from text                                       |
| TextStat                       | Calculates readability scores to evaluate text complexity                                       |
| NLLB (No Language Left Behind) | Translates text across multiple languages with high accuracy, supporting low-resource languages |

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.10+
- Git  
- (Optional) GPU support  



### 🧑‍💻 Local Setup

```bash
git clone <repository-link>
cd PolicyNav
pip install -r requirements.txt
```
## 🔐 Configuration & Environment Setup

To securely run the application (especially in Google Colab), you need to configure environment variables using **Ngrok** and **Gmail App Passwords**.



### 🌐 Ngrok Setup (for Public URL)

Ngrok is used to expose your Streamlit app running in Colab to the internet.

#### Steps to Get Ngrok Auth Token:

1. Visit: https://ngrok.com/  
2. Create a free account and log in  
3. Go to the **Dashboard**  
4. Copy your **Authtoken**



### 🔑 Add Ngrok Secret in Google Colab

1. Open your notebook in **Google Colab**  
2. Click the **🔐 Secrets (key icon)** in the left sidebar  
3. Click **“Add new secret”**  
4. Enter:

| Key | Value |
|--||
| `NGROK_AUTH_TOKEN` | Your copied ngrok token |

5. Save and enable access



### 📧 Gmail App Password Setup

Used for sending emails (OTP, verification, alerts).

#### Steps to Generate App Password:

1. Go to **Google Account → Security**  
2. Enable **2-Step Verification** (required)  
3. Search for **App Passwords**  
4. Select app type (e.g., *Mail*)  
5. Generate password  
6. Copy the **16-digit password immediately**

⚠️ Important:
- Do NOT use your normal Gmail password  
- You cannot view this password again after closing  



### 🔑 Add Gmail Secrets in Colab

Add the following secrets:

| Key | Value |
|--||
| `EMAIL_ID` | Your Gmail address |
| `EMAIL_APP_PASSWORD` | 16-digit app password |



### 📦 Final Environment Variables

Your configuration should include:

```env
NGROK_AUTH_TOKEN=your_ngrok_token
JWT_SECRET_KEY=your_secret_key
EMAIL_ID=your_email@gmail.com
EMAIL_APP_PASSWORD=your_app_password
```

## 📝 Usage Guide

1️⃣ **Register / Login** — Create an account with email, username, and a strong password (min. 8 chars, uppercase + number required)

2️⃣ **Select a Feature** from the sidebar — RAG Search, Summarization, Knowledge Graph, Readability Analyzer, or History

3️⃣ **RAG Search** — Type your policy question in any supported language. Choose output language and optionally enable **Simplify Jargon** mode. The AI searches the vector DB and translates the answer back.

4️⃣ **Summarizer** — Upload a policy PDF or paste text, select output language, and get a 3-bullet summary. Use the Q&A box to ask follow-up questions from the same document.

5️⃣ **Knowledge Graph** — Click **Render Interactive Topology** to generate a live force-directed entity graph from all ingested documents. Hover nodes for details.

6️⃣ **Readability Analyzer** — Enter text or upload a PDF/TXT. View 5 readability gauges, grade level classification (Beginner / Intermediate / Advanced / Expert), and detailed text statistics.

7️⃣ **Profile** — Manage your avatar, change email (OTP-verified), update password (with history check), and configure app settings.

8️⃣ **Feedback** — Submit a 5-star rating and optional comment after using any feature.

📌 *Screenshots included below 👇*


## 📊 Datasets & Evaluation

### 📁 Datasets Used

| Dataset | Usage |
|--------|------|
| Policy Documents (Custom) | RAG search corpus |
| Government Reports | Real-world testing |
| Web Scraped Docs | Knowledge graph generation |


### 📈 Evaluation Metrics

- Semantic relevance (**RAG accuracy**)  
- Response quality (**LLM output**)  
- Readability score improvements  
- Knowledge graph completeness  


## 📸 Screenshots

### 📊 Dashboard
![Dashboard](images/dashboard.png)



### 🔎 RAG Search
![RAG Search](images/rag_search.png)



### 🌐 Knowledge Graph
![Knowledge Graph](images/knowledge_graph.png)



### 🕘 History
![History](images/history.png)



### 🛠 Admin Panel
![Admin](images/admin.png)



### 🧠 Summarization
![Summarization](images/summarization.png)





## Mentor
Mohamedsipli M
## 👥 Team

| Name | Responsibilities |
|-------|----------------|
|Velagada Devi Sri Prasad  |  Admin dashboard, Data Visualization, Feed back Analysis |
| Aarti Ramesh chandolkar |User Dashboard, My profile page, readability, Docker|
| Kuruvaladoddi Ramya| knowledge graph, documentation |
| Savita Yadav|  Summarisation tab  |
| Pooja Kathirvel | rag search, Authentication |
| Sanjay janarthanan | History tab, Activity Tracking page |





## 📜 License

🆓 **MIT License**  
Free to use, modify, and distribute with attribution.
