# OCI Generative AI Professional - Study Guide

> **Certification Code**: 1Z0-1127-25
> **Target Audience**: Cloud Architects, AI/ML Engineers, Developers
> **Duration**: 90 minutes
> **Format**: Multiple Choice

---

## 📚 Table of Contents

1. [Fundamentals of Large Language Models](#fundamentals-of-llms)
2. [OCI Generative AI Service](#oci-generative-ai-service)
3. [Retrieval-Augmented Generation (RAG)](#rag-and-oracle-vector-search)
4. [OCI Generative AI Agents](#oci-generative-ai-agents)
5. [Cost Optimization & Sizing](#cost-optimization)
6. [Security & Governance](#security-and-governance)
7. [Practice Questions](#practice-questions)

---

## 1. Fundamentals of LLMs

### 1.1 What are Large Language Models?

**Definition**: Probabilistic models of text that compute distributions over vocabulary.

**Core Function**: Given input text, predict the most likely next word(s).

**"Large"**: Refers to the **number of trainable parameters** (typically billions).

### 1.2 LLM Architectures

| Architecture | Function | Use Cases | Examples |
|-------------|----------|-----------|----------|
| **Encoders** | Convert text → embeddings | Semantic search, classification, clustering | BERT, RoBERTa |
| **Decoders** | Generate text by predicting next token | Text generation, chat, code completion | GPT-4, Llama |
| **Encoder-Decoder** | Both encoding and decoding | Translation, sequence-to-sequence | T5, BART |

**Key Point**:
- **Encoders** → Best for **semantic search** and understanding
- **Decoders** → Best for **text generation**

### 1.3 Prompting & Prompt Engineering

**Prompting**: Changing model inputs to influence output.

**Prompt Engineering**: Refining inputs to get desired results.

#### Types of Prompting

| Type | Description | Example |
|------|-------------|---------|
| **Zero-shot** | Only task description, no examples | "Translate to French: Hello" |
| **Few-shot (k-shot)** | Include k examples | "cat→dog, hot→cold, big→?" |
| **Chain-of-Thought (CoT)** | Step-by-step reasoning | "Let's solve this step by step..." |
| **Zero-shot CoT** | Add "Let's think step by step" | Encourages reasoning without examples |

### 1.4 Decoding (Text Generation)

| Method | Description | Use Case |
|--------|-------------|----------|
| **Greedy Decoding** | Always pick the most probable token | Deterministic output |
| **Random Sampling** | Pick based on probability distribution | More diverse output |
| **Temperature** | Controls randomness (0=deterministic, 1=creative) | Balance creativity vs accuracy |
| **Top-k Sampling** | Choose from top-k highest probability tokens | Limited randomness |
| **Top-p (Nucleus)** | Choose from smallest set that adds up to p | Dynamic vocabulary |
| **Beam Search** | Generate multiple sequences, keep best | Higher quality output |

**Temperature Guidelines**:
- **Temperature = 0**: Completely deterministic
- **Temperature = 0.3-0.5**: Factual tasks
- **Temperature = 0.7-0.9**: Creative tasks
- **Temperature = 1.0**: Maximum randomness

### 1.5 Training & Fine-tuning Methods

| Method | Updates | Cost | Use Case |
|--------|---------|------|----------|
| **Fine-tuning** | All parameters | High | Best accuracy for specific tasks |
| **LoRA** | ~0.1-1% of parameters | Medium | Parameter-efficient tuning |
| **T-Few** | ~0.01% of parameters | Low | Oracle's efficient method |
| **Soft Prompting** | Special tokens only | Very Low | Task adaptation |
| **Continual Pretraining** | All parameters on new domain | Very High | Domain adaptation |

**Key Insight**: **T-Few** is Oracle's proprietary fine-tuning method that updates only ~0.01% of weights.

### 1.6 Key Challenges

| Challenge | Description | Mitigation |
|-----------|-------------|------------|
| **Hallucinations** | Generates fluent but incorrect info | Use RAG, grounding |
| **Bias** | Reflects training data biases | Content moderation, filtering |
| **Cost** | Training requires many GPUs | Use fine-tuning, not training from scratch |
| **Prompt Injection** | Malicious input manipulation | Input validation, sandboxing |
| **Data Leakage** | Exposure of training data | Privacy controls, data governance |

### 1.7 Evaluation Metrics

| Metric | Measures | Lower is Better? | Use Case |
|--------|----------|------------------|----------|
| **Perplexity** | How well model predicts tokens | ✅ Yes | Language modeling |
| **BLEU** | N-gram overlap (precision) | ❌ No | Translation |
| **ROUGE** | Recall/overlap | ❌ No | Summarization |
| **Accuracy/F1** | Classification performance | ❌ No | Classification |
| **Loss** | Prediction error | ✅ Yes | Training progress |

---

## 2. OCI Generative AI Service

### 2.1 Overview

**OCI Generative AI Service**: Fully managed, **serverless** platform for building generative AI apps.

**Key Features**:
- Single API for multiple foundation models (Cohere & Meta)
- No infrastructure management
- Pay-per-use pricing
- Built-in security and compliance

### 2.2 Pre-trained Foundation Models

#### Chat Models

| Model | Context Window | Parameters | Best For |
|-------|---------------|------------|----------|
| **Command-R** | 16k tokens | - | General chat, standard tasks |
| **Command-R-Plus** | **128k tokens** | - | Long documents, complex reasoning |
| **Meta Llama 3.1 (70B)** | 128k tokens | 70B | Open-source alternative |
| **Meta Llama 3.2/3.3** | Varies | Varies | Latest improvements |

**Important**: **Command-R-Plus** supports the **largest context window (128k tokens)**.

#### Embedding Models

**Purpose**: Convert text → vector representations for:
- Semantic search
- Clustering
- Classification
- RAG (Retrieval-Augmented Generation)

| Model | Languages | Dimensions | Input Limit |
|-------|-----------|------------|-------------|
| **Cohere embed-english** | English | 1024-d (standard), 384-d (lite) | 512 tokens/input |
| **Cohere embed-multilingual** | 100+ languages | 1024-d (standard), 384-d (lite) | 512 tokens/input |
| **V3 embed models** | Enhanced | 1024-d | Better for noisy data |

**Limits**:
- Max **512 tokens per input**
- Max **96 inputs per request**

### 2.3 Prompt Parameters

| Parameter | Function | Range | Effect |
|-----------|----------|-------|--------|
| **Temperature** | Controls randomness | 0-1 | 0=deterministic, 1=diverse |
| **Top-k** | Choose from top-k tokens | 1-n | Limits vocabulary |
| **Top-p** | Nucleus sampling | 0-1 | Dynamic token selection |
| **Frequency Penalty** | Reduces repetition by frequency | 0-1 | Based on how often token appears |
| **Presence Penalty** | Penalizes any repetition | 0-1 | Binary (appeared or not) |
| **Preamble Override** | Change tone/style | Text | "You are a pirate..." |

**Key Difference**:
- **Frequency Penalty**: Proportional to how many times token appeared
- **Presence Penalty**: Same penalty after first occurrence

### 2.4 Customization Options Comparison

| Approach | Training Required | Cost | Latency | Use Case |
|----------|------------------|------|---------|----------|
| **Prompting** | No | Free | Low | Quick experimentation |
| **RAG** | No | Low | Medium | Up-to-date knowledge |
| **Fine-tuning** | Yes | High | Low (after training) | Domain-specific tasks |
| **Training from Scratch** | Yes | Very High | Low | Not recommended |

**Best Practice**: **Don't train from scratch** - expensive and data-hungry.

### 2.5 Fine-tuning Workflow

```
1. Collect domain-specific training data
2. Upload to Object Storage
3. Launch fine-tuning job (choose base model + method)
4. Training runs on GPU cluster
5. Store fine-tuned weights (encrypted in Object Storage)
6. Register model in OCI Generative AI
7. Deploy to endpoint for inference
```

### 2.6 Inference Workflow

```
User sends prompt
    ↓
API Endpoint
    ↓
Model generates output (using decoding strategies)
    ↓
Response to user
    ↓
Optional: Logging, tracing, moderation, citations
```

### 2.7 Dedicated AI Clusters

#### Fine-Tuning Clusters

**Purpose**: Train/adapt models with custom data

**Billing**: Pay only for **duration of fine-tuning**

**Formula**:
```
Cost = Units × Hourly Rate × Hours
```

**Example**: Fine-tune with 8 units for 12 hours
```
Cost = 8 × $1/hr × 12 hrs = $96
```

#### Hosting (Inference) Clusters

**Purpose**: Serve models in production

**Billing**: Minimum **744 hours/month** (24×7 commitment)

**Formula**:
```
Cost = Units × Hourly Rate × 744 hrs/month
```

**Example**: Host with 2 units
```
Monthly Cost = 2 × $Y/hr × 744 hrs = 1,488 × Y
```

#### Cluster Types by Model

| Cluster Type | Model Family | Use Case |
|-------------|--------------|----------|
| **Small Cohere Dedicated** | Cohere (small) | Fine-tuning Command-R |
| **Large Cohere Dedicated** | Cohere (large) | Fine-tuning Command-R-Plus |
| **Large Meta Dedicated** | Meta Llama | Fine-tuning Llama models |
| **Embedding Cohere Dedicated** | Cohere Embed | Embedding tasks |

**Important**: **Llama models** use **Large Meta Dedicated** clusters.

### 2.8 GPU Sizing Guidelines

| Model Size | Parameters | Recommended Units |
|------------|-----------|-------------------|
| Small | ≤13B | 4-8 units |
| Medium | 30-70B | 8-16+ units |
| Large | 100B+ | 32+ units |

**Best Practice**: Run pilot jobs to estimate time & cost.

---

## 3. RAG and Oracle Vector Search

### 3.1 What is RAG?

**Retrieval-Augmented Generation**: Combines retrieval (search) + generation (LLM).

**Why RAG?**
- LLMs have **outdated training data**
- RAG retrieves **current, relevant information**
- Grounds answers in **enterprise data**
- **No retraining required**

### 3.2 RAG Pipeline Phases

```
1. INGESTION
   Load documents → Split into chunks → Create metadata

2. EMBEDDING & STORAGE
   Convert chunks → Vectors → Store in vector database

3. RETRIEVAL
   User query → Convert to vector → Similarity search → Top-K chunks

4. GENERATION
   LLM receives: Query + Retrieved chunks → Generate answer
```

### 3.3 LangChain Integration

#### Key Components

| Component | Purpose |
|-----------|---------|
| **PromptTemplate** | Single-string inputs |
| **ChatPromptTemplate** | Multi-turn conversations with roles |
| **Memory** | Maintain conversation history |
| **RetrievalQA** | Chain retrieval + LLM together |
| **VectorStore** | Store and search embeddings |

#### What is Memory?

- LLMs are **stateless** by default
- Memory **stores previous interactions**
- LangChain **passes history** back to model
- Enables **context-aware** conversations

**Memory Workflow**:
```
1. User asks question → LangChain records it
2. LLM generates response → Also recorded
3. Next interaction → Retrieves conversation history
4. History appended to new prompt → LLM sees context
```

### 3.4 Oracle 23ai Integration

#### SELECT AI

**Purpose**: Converts **natural language → SQL queries** using OCI Generative AI

**Example**:
```sql
SELECT AI "Show me all customers who spent more than $1000 last month"
```

#### Vector Store

**Purpose**: Store embeddings in **VECTOR datatype**

**Capabilities**:
- Similarity search (cosine, dot product)
- Native SQL integration
- Scalable vector indexing

### 3.5 Vector Indexes

#### HNSW (Hierarchical Navigable Small World)

**Type**: Graph-based neighbor index

**How it Works**: Each vector links to nearby vectors across multiple layers

**Pros**:
- Very fast ANN (Approximate Nearest Neighbor) search
- Strong recall at low latency
- Best for interactive RAG/chat

**Cons**:
- Requires memory for graph
- Build time increases with size

**Best For**: Low-latency Q&A, real-time semantic search

#### IVF (Inverted File)

**Type**: Partition/cluster-based index

**How it Works**: Routes query to most relevant partitions, then searches inside

**Pros**:
- Efficient at scale
- Good throughput for large collections
- Predictable query times

**Cons**:
- Recall depends on partitions probed
- Requires tuning

**Best For**: Very large collections (millions+ vectors)

### 3.6 Similarity Metrics

| Metric | Considers | Formula | Normalized? |
|--------|-----------|---------|-------------|
| **Dot Product** | Magnitude + Angle | a·b | No |
| **Cosine Similarity** | Angle only | a·b / (‖a‖‖b‖) | Yes |
| **Euclidean Distance** | Spatial distance | √Σ(ai-bi)² | No |

**When to Use**:
- **Cosine**: Magnitude-invariant, good for text
- **Dot Product**: When magnitude matters
- **Euclidean**: Spatial relationships

### 3.7 Text Chunking

**Why Chunk?**
- LLMs have **token limits**
- Smaller chunks = **more precise retrieval**
- **Overlap** maintains semantic continuity

**Best Practices**:
- Chunk size: **200-500 tokens**
- Overlap: **10-20%**
- Preserve sentence boundaries

**Tools**:
- `TextSplitter` (LangChain)
- `RecursiveCharacterTextSplitter`

### 3.8 RAG with Oracle DB 23ai

**Complete Workflow**:

```python
# 1. Setup
from langchain_community.embeddings import OCIGenAIEmbeddings
from langchain_community.vectorstores import OracleVS
from langchain.chains import RetrievalQA

# 2. Generate embeddings
embeddings = OCIGenAIEmbeddings(
    model_id="cohere.embed-english-v3.0",
    service_endpoint="https://..."
)

# 3. Store in Oracle Vector Store
vector_store = OracleVS(
    connection_string="...",
    embedding_function=embeddings,
    table_name="document_chunks"
)

# 4. Create retrieval chain
qa_chain = RetrievalQA.from_chain_type(
    llm=ChatOCIGenAI(...),
    retriever=vector_store.as_retriever(search_kwargs={"k": 3}),
    return_source_documents=True
)

# 5. Query
result = qa_chain({"query": "What is RAG?"})
```

**Key Points**:
- Same embedding model for **indexing and querying**
- Top-K retrieval (typically **k=3 to 5**)
- `return_source_documents=True` for **citations**

---

## 4. OCI Generative AI Agents

### 4.1 Overview

**OCI Generative AI Agents**: Fully managed service combining **LLMs + intelligent retrieval** for contextual, actionable responses.

**Purpose**: Automate tasks like:
- Booking
- Querying enterprise data
- Summarization
- Multi-step workflows

### 4.2 Core Architecture

```
User Interface (Chatbot/Web/Voice/API)
            ↓
    OCI GenAI Agent
            ↓
    ┌──────┴──────┐
    ↓             ↓
Knowledge Base   Tools/Actions
    ↓             ↓
External Data   External APIs
```

**Key Components**:
- **LLM**: Reasoning and generation
- **RAG**: Retrieval from knowledge base
- **Memory**: Conversation context
- **Tools**: External API calls
- **Feedback Loop**: Improve responses

### 4.3 Key Concepts

| Concept | Definition |
|---------|------------|
| **Generative AI Model** | LLM trained on large data for NLU + NLG |
| **Agent** | Autonomous system = LLM + RAG + Tools |
| **Answerability** | Model responds relevantly to queries |
| **Groundedness** | Responses traceable to data sources |

### 4.4 Data Access Hierarchy

```
Data Store (Where data resides)
    ↓
Data Source (Connection details)
    ↓
Knowledge Base (Vector storage system)
    ↓
Agent (Uses KB for retrieval)
```

### 4.5 Supported Data Sources

| Data Source | Description | File Types | Limits |
|-------------|-------------|------------|--------|
| **OCI Object Storage** | Managed ingestion | PDF, TXT | ≤100MB per file |
| **OCI OpenSearch** | Bring-your-own index | Any | Pre-indexed |
| **Oracle DB 23ai Vector Store** | Custom embeddings | Structured | SQL-based retrieval |

**Object Storage Requirements**:
- Max **1,000 files** per source
- Max **100MB** per file
- Supported: **PDF, TXT**
- Images in PDFs: **Ignored**

### 4.6 Data Ingestion

**Process**: Extract → Transform → Store into knowledge base

**Hybrid Search** = **Lexical + Semantic** search
- **Lexical**: Keyword matching (exact words)
- **Semantic**: Meaning-based (embeddings)
- **Combined**: Higher accuracy

**Ingestion Jobs**:
- Add new documents
- Retry failed ingestions
- Update existing documents
- Cancel running jobs

### 4.7 Additional Features

| Feature | Purpose | Default/Limit |
|---------|---------|---------------|
| **Session** | Maintains context across exchanges | Timeout: 1hr-7d (default: 3,600s) |
| **Endpoint** | Access point for external apps | One per agent |
| **Trace** | Logs full conversation history | For debugging |
| **Citation** | Sources of responses | Transparency |
| **Content Moderation** | Filters harmful content | Input, output, or both |

### 4.8 Database Guidelines (Oracle 23ai)

**Table Structure**:
```sql
CREATE TABLE chunks (
    DOCID VARCHAR2(100),
    body CLOB,
    vector VECTOR(1024, FLOAT32)
);
```

**Requirements**:
- Same **embedding model** for indexing and querying
- Define **retrieval function** (PL/SQL)
- Returns: `DOCID`, `body`, `score`
- Supports: **Cosine similarity** or **Euclidean distance**

**Example Retrieval Function**:
```sql
CREATE FUNCTION vector_search(
    query_vector VECTOR,
    top_k NUMBER
) RETURN SYS_REFCURSOR
AS
    results SYS_REFCURSOR;
BEGIN
    OPEN results FOR
        SELECT DOCID, body, VECTOR_DISTANCE(vector, query_vector, COSINE) as score
        FROM chunks
        ORDER BY score
        FETCH FIRST top_k ROWS ONLY;
    RETURN results;
END;
```

### 4.9 Agent Workflow

```
1. Create Knowledge Base
   → Choose data store (Object Storage, Oracle DB, OpenSearch)

2. Ingest Data
   → Upload PDFs/TXTs or vectorized data

3. Create Agent
   → Define welcome message
   → Select knowledge base
   → Configure model

4. Create Endpoint
   → Configure session timeout
   → Enable moderation, trace, citation

5. Chat & Test
   → Query agent
   → View responses, citations, trace
```

### 4.10 Default Limits

| Resource | Limit |
|----------|-------|
| **Data sources** | 1 per knowledge base |
| **Files** | 1,000 per source |
| **File size** | 100MB each |
| **Session timeout** | 3,600s (default), up to 7 days |

### 4.11 Content Moderation

**Purpose**: Filter harmful content

**Applies To**:
- **Input**: User prompts
- **Output**: Agent responses
- **Both**: Full protection

**Categories**:
- Hate speech
- Violence
- Sexual content
- Self-harm
- Illegal activities

### 4.12 Groundedness vs Hallucination

| Concept | Definition | How to Ensure |
|---------|------------|---------------|
| **Groundedness** | Responses traceable to sources | Use RAG, enable citations |
| **Hallucination** | Invented/incorrect information | Restrict to retrieved context |

**Best Practice**: Use **RAG + Citations** to ensure groundedness.

### 4.13 Agent vs Chatbot

| Feature | Chatbot | Agent |
|---------|---------|-------|
| **Context** | May maintain | ✅ Maintains |
| **External Tools** | ❌ No | ✅ Yes |
| **RAG** | Optional | ✅ Built-in |
| **Reasoning** | Limited | ✅ Advanced |
| **Multi-step** | ❌ No | ✅ Yes |

**Key Difference**: Agents can **call external APIs/tools** during reasoning.

---

## 5. Cost Optimization

### 5.1 Model Selection Strategy

| Task Complexity | Recommended Model | Reason |
|----------------|-------------------|--------|
| Simple Q&A | Smaller model (Command-R) | Lower cost |
| Complex reasoning | Larger model (Command-R-Plus) | Better accuracy |
| Code generation | Specialized code model | Domain expertise |
| Translation | Encoder-decoder | Architecture match |

**Principle**: Use **smallest model** that meets requirements.

### 5.2 Fine-tuning Cost Calculation

```
Cost = Units × Hourly Rate × Hours
```

**Factors**:
- Model size (more parameters = more units)
- Dataset size (more tokens = longer training)
- Method (LoRA/T-Few = cheaper)

**Optimization**:
- Use **T-Few or LoRA** (parameter-efficient)
- Run **pilot jobs** to estimate
- Use **smaller base model** if possible

### 5.3 Hosting Cost Calculation

```
Monthly Cost = Units × Hourly Rate × 744 hrs
```

**Commitment**: Minimum **744 hours/month** (24×7)

**Optimization**:
- Use **on-demand inference** for low traffic
- Use **dedicated hosting** for high traffic
- Deploy **regionally** to reduce latency

### 5.4 RAG vs Fine-tuning Cost

| Aspect | RAG | Fine-tuning |
|--------|-----|-------------|
| **Initial Cost** | Low | High |
| **Ongoing Cost** | Storage + queries | Hosting |
| **Update Cost** | Re-index documents | Re-train model |
| **Time to Deploy** | Hours | Days |
| **Best For** | Dynamic data | Static domain |

**Rule of Thumb**: Use **RAG first**, fine-tune only if necessary.

---

## 6. Security and Governance

### 6.1 IAM (Identity and Access Management)

**Access Control**:
- **Dynamic Groups**: Allow agents to access resources
- **Policies**: Grant specific permissions
- **Principle of Least Privilege**: Minimum necessary access

**Example Policy**:
```
Allow dynamic-group genai-agents to read objects in compartment knowledge-base
Allow dynamic-group genai-agents to use generative-ai-family in tenancy
```

### 6.2 Data Privacy

**Customer Data**:
- **Never used** to train Oracle's base models
- **Stored within** your tenancy
- **Encrypted** at rest and in transit

**Fine-tuned Models**:
- Weights stored in **your Object Storage**
- Encrypted with **OCI Key Management (Vault)**
- **Isolated** from other tenants

### 6.3 OCI Key Management (Vault)

**Purpose**: Securely manage encryption keys

**Use Cases**:
- Encrypt fine-tuned model weights
- Encrypt data in Object Storage
- Encrypt vector database

**Key Types**:
- **Master Keys**: Managed by OCI
- **Customer-Managed Keys**: You control rotation

### 6.4 Network Security

**Private Endpoints**:
- Deploy models **within VCN**
- **No public internet** exposure
- Access via **private IPs only**

**Use Case**: Compliance requirements (healthcare, finance)

### 6.5 Content Moderation

**Applies To**:
- User inputs (prevent prompt injection)
- Model outputs (filter harmful content)

**Categories**:
- Hate speech
- Violence
- Sexual content
- Self-harm

### 6.6 Governance Framework

**Oracle References**: **NIST AI Risk Management Framework (AI RMF)**

**Best Practices**:
- Document model decisions
- Monitor for bias
- Regular audits
- Incident response plan

### 6.7 Compliance

**Certifications**:
- ISO 27001
- SOC 1/2/3
- GDPR compliant
- HIPAA eligible (with BAA)

**Data Residency**: Choose region for data storage

---

## 7. Practice Questions

### Set 1: Fundamentals (10 Questions)

**Q1**. What does "large" in LLM primarily refer to?
a) Vocabulary size
b) Training dataset size
c) Number of parameters ✅
d) Number of GPUs used

**Q2**. Which architecture is best suited for semantic search?
a) Decoder
b) Encoder ✅
c) Encoder-Decoder
d) Random Forest

**Q3**. Which prompting technique encourages step-by-step reasoning?
a) Chain-of-Thought prompting ✅
b) Zero-shot prompting
c) Greedy prompting
d) LoRA prompting

**Q4**. What does temperature control in decoding?
a) The speed of model training
b) The size of the vocabulary
c) The randomness of token selection ✅
d) The number of parameters updated

**Q5**. Which training method adds new parameters without changing original ones?
a) Fine-tuning
b) LoRA
c) Soft Prompting ✅
d) Continual Pretraining

**Q6**. Which decoding method always picks the most likely token?
a) Random Sampling
b) Beam Search
c) Greedy Decoding ✅
d) Nucleus Sampling

**Q7**. Which fine-tuning method updates only ~0.01% of weights?
a) Vanilla fine-tuning
b) T-Few ✅
c) LoRA
d) Zero-shot prompting

**Q8**. Which evaluation metric is commonly used for summarization?
a) BLEU
b) Accuracy
c) ROUGE ✅
d) Perplexity

**Q9**. What is a known risk of deploying LLMs?
a) Faster processing
b) Prompt Injection ✅
c) Higher accuracy
d) Lower memory usage

**Q10**. Which model is an example of a decoder architecture?
a) BERT
b) GPT-4 ✅
c) ResNet
d) Word2Vec

---

### Set 2: OCI Generative AI Service (10 Questions)

**Q11**. Which OCI chat model supports up to 128k tokens per input?
a) Command-R (16k)
b) Command-R-Plus ✅
c) Llama 3.1 (70B)
d) Cohere embed-english

**Q12**. What is the main use case for embedding models?
a) Conversational chat
b) Text-to-image
c) Semantic search ✅
d) Translation only

**Q13**. Which parameter controls the randomness of the output?
a) Frequency penalty
b) Temperature ✅
c) Top-k
d) Context length

**Q14**. What is a major advantage of RAG?
a) Eliminates the cost of GPUs
b) Provides grounded answers with enterprise data ✅
c) Removes the need for tokenization
d) Always reduces latency

**Q15**. Which parameter reduces repeated phrases based on count?
a) Temperature
b) Top-p
c) Frequency penalty ✅
d) Presence penalty

**Q16**. What is the minimum hosting commitment for OCI clusters?
a) 1 hour
b) 10 hours
c) 744 hours ✅
d) 96 hours

**Q17**. Which cluster type is used for Llama models?
a) Large Cohere Dedicated
b) Small Cohere Dedicated
c) Large Meta Dedicated ✅
d) Embedding Cohere Dedicated

**Q18**. Which OCI service manages encryption keys for fine-tuned models?
a) OCI IAM
b) OCI Object Storage
c) OCI Key Management (Vault) ✅
d) OCI Data Guard

**Q19**. What is the maximum file size for Object Storage ingestion?
a) 10 MB
b) 50 MB
c) 100 MB ✅
d) Unlimited

**Q20**. Which statement is true about OCI GenAI data privacy?
a) Data may be used for training
b) Customer data is never used to train base models ✅
c) Data is shared across tenants
d) Data must leave tenant boundary

---

### Set 3: RAG & LangChain (10 Questions)

**Q21**. Which LangChain component preserves conversation context?
a) Prompt Template
b) Memory ✅
c) Chain
d) Vector Store

**Q22**. Which template is designed for conversational inputs?
a) Prompt Template
b) ChainTemplate
c) ChatPromptTemplate ✅
d) DialogueTemplate

**Q23**. Which Oracle feature converts natural language to SQL?
a) Oracle Cloud Guard
b) Oracle Data Guard
c) Oracle SELECT AI ✅
d) Oracle AutoML

**Q24**. Which similarity metric considers both magnitude and angle?
a) Cosine Similarity
b) Dot Product ✅
c) Euclidean Distance
d) Jaccard Index

**Q25**. Why is chunk overlap used in text splitting?
a) To reduce cost
b) To maintain semantic continuity ✅
c) To increase retrieval speed
d) To avoid indexing

**Q26**. What type of index is HNSW?
a) Partition-based index
b) Graph-based neighbor index ✅
c) Flat index
d) Semantic index

**Q27**. What is the role of embeddings in RAG?
a) Tokenize text
b) Convert text to vectors for similarity search ✅
c) Generate SQL queries
d) Reduce context window

**Q28**. Which LangChain class chains retrieval + LLM?
a) ChatPromptTemplate
b) RetrievalQA ✅
c) MemoryChain
d) OracleVS

**Q29**. Which Oracle 23ai datatype stores embeddings?
a) BLOB
b) JSON
c) VECTOR ✅
d) VARCHAR

**Q30**. What must align between queries and stored vectors?
a) File formats
b) Table schemas
c) Embedding models ✅
d) Indexing methods

---

### Set 4: OCI Generative AI Agents (10 Questions)

**Q31**. What is a Knowledge Base in OCI GenAI Agents?
a) Collection of rules
b) Vector-indexed datastore ✅
c) Pre-trained knowledge
d) Conversation log

**Q32**. Which feature ensures responses are traceable?
a) Trace
b) Persona
c) Groundedness ✅
d) Content Moderation

**Q33**. What maintains continuity in conversations?
a) Prompt
b) Tools
c) Memory ✅
d) Citation

**Q34**. Which OCI service allows PDF/TXT ingestion?
a) OCI IAM
b) OCI Object Storage ✅
c) OCI Vault
d) OCI Logging

**Q35**. Hybrid search combines:
a) Semantic + Lexical search ✅
b) Vector + Image search
c) RAG + Prompt engineering
d) SQL + Graph search

**Q36**. What defines connection details for data retrieval?
a) Knowledge Base
b) Data Store
c) Data Source ✅
d) Embedding Model

**Q37**. What is the default session timeout?
a) 300 seconds
b) 1 hour (3,600 seconds) ✅
c) 24 hours
d) 7 days

**Q38**. Which feature tracks conversation history?
a) Trace ✅
b) Session
c) Content Moderation
d) Endpoint

**Q39**. Which search method is meaning-based?
a) Lexical
b) Semantic ✅
c) Hybrid
d) Full-text

**Q40**. What can Agents do that chatbots cannot?
a) Maintain context
b) Generate text
c) Call external APIs/tools ✅
d) Translate languages

---

### Set 5: Advanced & Scenario-Based (10 Questions)

**Q41**. You deploy a model in a healthcare environment requiring no internet exposure. Which deployment option is best?
a) Public endpoint with security lists
b) Private endpoint within VCN ✅
c) Base model only
d) Object Storage with signed URLs

**Q42**. Files in Object Storage contain multilingual text and diagrams. What will the Agent ingest?
a) All content including diagrams
b) Text only; diagrams ignored ✅
c) Only UTF-8 labeled text
d) Only English text

**Q43**. Which task requires embedding models, not generative LLMs?
a) Summarizing text
b) Sentiment classification
c) Similarity search over knowledge bases ✅
d) Answering questions

**Q44**. Which mitigation best reduces hallucination?
a) Increase temperature
b) Restrict to retrieval-augmented context ✅
c) Disable embeddings
d) Use embedding-only responses

**Q45**. To allow an Agent to access Object Storage, which IAM principle is required?
a) OBJECT_WRITE and OBJECT_DELETE
b) OBJECT_READ access to Agent's dynamic group ✅
c) Tenancy-level ADMIN
d) No IAM permissions needed

**Q46**. Your fine-tuned sentiment model misclassifies slang. What is the best mitigation?
a) Increase beam size
b) Collect new training data with slang and retrain ✅
c) Adjust Object Storage policies
d) Switch to embedding model

**Q47**. Which framework does Oracle reference for AI governance?
a) COBIT 2019
b) NIST AI Risk Management Framework ✅
c) ITIL v4
d) ISO 22301

**Q48**. If you update a PDF in Object Storage linked to a knowledge base, what must you do?
a) Nothing; syncs automatically
b) Re-trigger ingestion job ✅
c) Delete and recreate knowledge base
d) Update IAM policy

**Q49**. Which fine-tuning method is most cost-efficient?
a) Vanilla fine-tuning
b) T-Few ✅
c) Continual pretraining
d) Training from scratch

**Q50**. When is RAG preferred over fine-tuning?
a) Static domain knowledge
b) Dynamic, frequently updated data ✅
c) Maximum customization needed
d) No external data available

---

## 8. Key Formulas & Numbers

### Cost Calculations

**Fine-tuning Cost**:
```
Cost = Units × Hourly Rate × Hours
```

**Hosting Cost**:
```
Monthly Cost = Units × Hourly Rate × 744 hrs
```

### Important Limits

| Resource | Limit |
|----------|-------|
| **Command-R-Plus context** | 128k tokens |
| **Embedding input** | 512 tokens |
| **Max embeddings per request** | 96 inputs |
| **Object Storage file size** | 100 MB |
| **Files per data source** | 1,000 |
| **Default session timeout** | 3,600s (1 hour) |
| **Hosting commitment** | 744 hrs/month |

### GPU Sizing

| Model Size | Units |
|------------|-------|
| ≤13B params | 4-8 |
| 30-70B params | 8-16+ |
| 100B+ params | 32+ |

---

## 9. Exam Tips

### 1. Focus Areas by Weight

**High Priority** (40-50% of exam):
- OCI Generative AI Service architecture
- RAG implementation
- Fine-tuning vs other approaches
- Agent capabilities

**Medium Priority** (30-40%):
- LLM fundamentals
- Prompt engineering
- Cost optimization
- Security & IAM

**Lower Priority** (10-20%):
- Specific code syntax
- Exact pricing numbers
- Detailed API calls

### 2. Common Traps

**Trap**: Confusing **Frequency Penalty** vs **Presence Penalty**
- **Frequency**: Proportional to occurrence count
- **Presence**: Binary (appeared or not)

**Trap**: Confusing **Encoder** vs **Decoder**
- **Encoder**: Embeddings, search
- **Decoder**: Text generation

**Trap**: Assuming **Agents auto-sync** with Object Storage
- Must **re-trigger ingestion** after updates

**Trap**: Thinking **customer data** is used for training
- **Never used** to train Oracle's base models

### 3. Calculation Questions

**Be Ready For**:
- Fine-tuning cost given units, rate, hours
- Hosting cost for 744 hrs/month
- Choosing cluster type based on model
- GPU units based on parameter count

### 4. Scenario-Based Questions

**Common Scenarios**:
- Choosing between RAG vs fine-tuning
- Private endpoint for compliance
- Reducing hallucination
- Cost optimization
- IAM for Agent access

### 5. Keywords to Watch

| Keyword | Likely Answer |
|---------|---------------|
| "No internet exposure" | Private endpoint |
| "Outdated information" | RAG |
| "Cost-efficient tuning" | T-Few or LoRA |
| "128k tokens" | Command-R-Plus |
| "Traceable to sources" | Groundedness, Citations |
| "Step-by-step reasoning" | Chain-of-Thought |
| "~0.01% weights" | T-Few |
| "744 hours" | Hosting commitment |
| "Llama models" | Large Meta Dedicated |
| "Encryption keys" | OCI Key Management |

---

## 10. Quick Reference Tables

### Model Selection Guide

| Use Case | Recommended Model |
|----------|-------------------|
| Short conversations | Command-R (16k) |
| Long documents | Command-R-Plus (128k) |
| Semantic search | Cohere embed models |
| Code generation | Specialized code model |
| Multilingual | embed-multilingual |

### When to Use What

| Approach | When to Use |
|----------|-------------|
| **Prompting** | Quick experiments, no training |
| **RAG** | Dynamic data, citations needed |
| **Fine-tuning** | Domain-specific, static knowledge |
| **From Scratch** | Never (too expensive) |

### Data Source Comparison

| Source | Managed | File Types | Pre-processing |
|--------|---------|------------|----------------|
| **Object Storage** | Yes | PDF, TXT | Automatic |
| **OpenSearch** | No | Any | You manage |
| **Oracle 23ai** | No | Structured | Custom functions |

---

## 12. Additional Resources

### Official Documentation
- [OCI Generative AI Documentation](https://docs.oracle.com/en-us/iaas/Content/generative-ai/home.htm)
- [OCI Generative AI Agents](https://docs.oracle.com/en-us/iaas/Content/generative-ai-agents/home.htm)
- [Oracle Database 23ai Vector Search](https://docs.oracle.com/en/database/oracle/oracle-database/23/vecse/)

### Practice Platforms
- Oracle Learning Library
- Oracle Cloud Free Tier (hands-on practice)
- Quizlet flashcards (search "Oracle Generative AI Professional")
---

## Final Checklist

Before the exam, ensure you can:

- [ ] Explain **Encoder vs Decoder** architectures
- [ ] List **prompting techniques** and when to use each
- [ ] Calculate **fine-tuning and hosting costs**
- [ ] Describe **RAG pipeline** phases
- [ ] Compare **HNSW vs IVF** indexes
- [ ] Explain **Cosine vs Dot Product** similarity
- [ ] List **OCI Generative AI chat models** and context limits
- [ ] Describe **T-Few** fine-tuning method
- [ ] Explain **Agent vs Chatbot** differences
- [ ] List **supported data sources** for Agents
- [ ] Describe **hybrid search** (Lexical + Semantic)
- [ ] Explain **Groundedness** and how to ensure it
- [ ] Configure **IAM policies** for Agent access
- [ ] Choose **private endpoint** for compliance
- [ ] Reduce **hallucination** using RAG
- [ ] Update **knowledge base** after file changes
- [ ] Differentiate **Frequency vs Presence Penalty**
- [ ] Select **cluster type** for Llama models
- [ ] Use **OCI Key Management** for encryption
- [ ] Apply **NIST AI RMF** governance framework

---

**Good luck with your OCI Generative AI Professional certification!**

*Last updated: 2025-10-20*
