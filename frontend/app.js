// Key generation and crypto helpers
async function generateKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
    );
}

async function exportKey(key, format) {
    const exported = await window.crypto.subtle.exportKey(format, key);
    return arrayBufferToBase64(exported);
}

async function signData(privateKey, data) {
    const encoder = new TextEncoder();
    const encoded = encoder.encode(data);
    const signature = await window.crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        encoded
    );
    return arrayBufferToBase64(signature);
}

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Components
function Navbar({ user, onLogout }) {
    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
            <div className="container-fluid">
                <a className="navbar-brand" href="#">Eutelos</a>
                <div className="d-flex align-items-center">
                    {user && (
                        <>
                            <span className="text-light me-3">
                                {user.name} ({user.role})
                            </span>
                            <button 
                                className="btn btn-outline-light" 
                                onClick={onLogout}
                            >
                                Logout
                            </button>
                        </>
                    )}
                </div>
            </div>
        </nav>
    );
}

function LoginPage({ onLogin, onNavigate }) {
    const [email, setEmail] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        await onLogin(email);
        setLoading(false);
    };
    
    return (
        <div className="row justify-content-center mt-5">
            <div className="col-md-6">
                <div className="card shadow">
                    <div className="card-body">
                        <h2 className="text-center mb-4">Login</h2>
                        <form onSubmit={handleSubmit}>
                            <div className="mb-3">
                                <label className="form-label">Email</label>
                                <input 
                                    type="email" 
                                    className="form-control"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                />
                            </div>
                            <button 
                                type="submit" 
                                className="btn btn-primary w-100"
                                disabled={loading}
                            >
                                {loading ? 'Logging in...' : 'Login'}
                            </button>
                            <div className="mt-3 text-center">
                                <button 
                                    type="button" 
                                    className="btn btn-link" 
                                    onClick={onNavigate}
                                >
                                    Don't have an account? Register
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
}

function RegisterPage({ onRegister, onNavigate }) {
    const [name, setName] = React.useState('');
    const [email, setEmail] = React.useState('');
    const [role, setRole] = React.useState('client');
    const [loading, setLoading] = React.useState(false);
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        
        try {
            const keyPair = await generateKeyPair();
            const publicKey = await exportKey(keyPair.publicKey, "spki");
            const privateKey = await exportKey(keyPair.privateKey, "pkcs8");
            
            await onRegister(name, email, role, publicKey, privateKey);
        } catch (error) {
            console.error("Registration failed:", error);
            alert("Registration failed. Please try again.");
        }
        
        setLoading(false);
    };
    
    return (
        <div className="row justify-content-center mt-5">
            <div className="col-md-6">
                <div className="card shadow">
                    <div className="card-body">
                        <h2 className="text-center mb-4">Register</h2>
                        <form onSubmit={handleSubmit}>
                            <div className="mb-3">
                                <label className="form-label">Name</label>
                                <input 
                                    type="text" 
                                    className="form-control"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="mb-3">
                                <label className="form-label">Email</label>
                                <input 
                                    type="email" 
                                    className="form-control"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="mb-3">
                                <label className="form-label">Role</label>
                                <select 
                                    className="form-select"
                                    value={role}
                                    onChange={(e) => setRole(e.target.value)}
                                >
                                    <option value="client">Client</option>
                                    <option value="freelancer">Freelancer</option>
                                </select>
                            </div>
                            <button 
                                type="submit" 
                                className="btn btn-primary w-100"
                                disabled={loading}
                            >
                                {loading ? 'Registering...' : 'Register'}
                            </button>
                            <div className="mt-3 text-center">
                                <button 
                                    type="button" 
                                    className="btn btn-link" 
                                    onClick={onNavigate}
                                >
                                    Already have an account? Login
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
}

function DashboardPage({ user, onLogout, onViewJobs, onCreateJob, onViewAdmin }) {
    return (
        <div className="container">
            <h1 className="text-center mb-4">Welcome to Eutelos</h1>
            
            <div className="card shadow">
                <div className="card-body">
                    <h2>Your Dashboard</h2>
                    <div className="mb-4">
                        <p><strong>Name:</strong> {user.name}</p>
                        <p><strong>Email:</strong> {user.email}</p>
                        <p><strong>Role:</strong> 
                            <span className={`badge ${user.role === 'admin' ? 'bg-danger' : 'bg-primary'} ms-2`}>
                                {user.role}
                            </span>
                        </p>
                    </div>
                    
                    <div className="d-flex gap-3">
                        {user.role === 'client' && (
                            <button 
                                className="btn btn-primary" 
                                onClick={onCreateJob}
                            >
                                Create New Job
                            </button>
                        )}
                        <button 
                            className="btn btn-secondary" 
                            onClick={onViewJobs}
                        >
                            View All Jobs
                        </button>
                        {user.role === 'admin' && (
                            <button 
                                className="btn btn-warning" 
                                onClick={onViewAdmin}
                            >
                                Admin Panel
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

function JobsPage({ jobs, onBack }) {
    const [jobList, setJobList] = React.useState([]);
    const [loading, setLoading] = React.useState(true);

    React.useEffect(() => {
        const fetchJobs = async () => {
            try {
                const response = await axios.get('/jobs');
                setJobList(response.data);
                setLoading(false);
            } catch (error) {
                console.error('Failed to fetch jobs:', error);
                setLoading(false);
            }
        };
        fetchJobs();
    }, []);

    if (loading) {
        return (
            <div className="container mt-5 text-center">
                <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                </div>
                <p>Loading jobs...</p>
            </div>
        );
    }

    return (
        <div className="container">
            <div className="d-flex justify-content-between align-items-center mb-4">
                <h1>Available Jobs</h1>
                <button 
                    className="btn btn-outline-secondary" 
                    onClick={onBack}
                >
                    Back to Dashboard
                </button>
            </div>
            
            {jobList.length === 0 ? (
                <div className="alert alert-info">
                    No jobs available at the moment. Check back later!
                </div>
            ) : (
                <div className="row">
                    {jobList.map(job => (
                        <div key={job.id} className="col-md-6 mb-4">
                            <div className="card h-100 shadow">
                                <div className="card-body">
                                    <h5 className="card-title">
                                        {job.title}
                                        <span className={`badge ms-2 ${
                                            job.status === 'open' ? 'bg-success' : 'bg-secondary'
                                        }`}>
                                            {job.status}
                                        </span>
                                    </h5>
                                    <p className="card-text">{job.description}</p>
                                    <ul className="list-group list-group-flush mb-3">
                                        <li className="list-group-item">
                                            <strong>Budget:</strong> ${job.budget.toFixed(2)}
                                        </li>
                                        <li className="list-group-item">
                                            <strong>Deadline:</strong> {job.deadline}
                                        </li>
                                        <li className="list-group-item">
                                            <strong>Client:</strong> {job.clientName || `User #${job.clientId}`}
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function CreateJobPage({ onCreate, onCancel }) {
    const [title, setTitle] = React.useState('');
    const [description, setDescription] = React.useState('');
    const [budget, setBudget] = React.useState('');
    const [deadline, setDeadline] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        
        try {
            const privateKeyBase64 = localStorage.getItem('privateKey');
            const privateKeyBuffer = base64ToArrayBuffer(privateKeyBase64);
            
            const privateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                privateKeyBuffer,
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: "SHA-256"
                },
                true,
                ["sign"]
            );

            const dataToSign = `${title}|${description}|${parseFloat(budget).toFixed(2)}|${deadline}|${JSON.parse(localStorage.getItem('user')).id}`;
            const signature = await signData(privateKey, dataToSign);

            const success = await onCreate({
                title,
                description,
                budget: parseFloat(budget),
                deadline,
                signature
            });
            
            if (success) {
                setTitle('');
                setDescription('');
                setBudget('');
                setDeadline('');
            }
        } catch (error) {
            alert('Job creation failed: ' + error.message);
        }
        
        setLoading(false);
    };
    
    return (
        <div className="container">
            <div className="d-flex justify-content-between align-items-center mb-4">
                <h1>Create New Job</h1>
                <button 
                    className="btn btn-outline-secondary" 
                    onClick={onCancel}
                >
                    Cancel
                </button>
            </div>
            
            <div className="card shadow">
                <div className="card-body">
                    <form onSubmit={handleSubmit}>
                        <div className="mb-3">
                            <label className="form-label">Job Title</label>
                            <input 
                                type="text" 
                                className="form-control"
                                value={title}
                                onChange={(e) => setTitle(e.target.value)}
                                required
                            />
                        </div>
                        <div className="mb-3">
                            <label className="form-label">Description</label>
                            <textarea 
                                className="form-control"
                                rows="4"
                                value={description}
                                onChange={(e) => setDescription(e.target.value)}
                                required
                            ></textarea>
                        </div>
                        <div className="row mb-3">
                            <div className="col-md-6">
                                <label className="form-label">Budget ($)</label>
                                <input 
                                    type="number" 
                                    className="form-control"
                                    value={budget}
                                    onChange={(e) => setBudget(e.target.value)}
                                    required
                                    min="1"
                                    step="0.01"
                                />
                            </div>
                            <div className="col-md-6">
                                <label className="form-label">Deadline</label>
                                <input 
                                    type="date" 
                                    className="form-control"
                                    value={deadline}
                                    onChange={(e) => setDeadline(e.target.value)}
                                    required
                                />
                            </div>
                        </div>
                        <button 
                            type="submit" 
                            className="btn btn-primary"
                            disabled={loading}
                        >
                            {loading ? 'Creating...' : 'Create Job'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}

function AdminPanel({ onBack }) {
    const [adminData, setAdminData] = React.useState({ users: [], jobs: [] });
    const [loading, setLoading] = React.useState(true);
    const [selectedUser, setSelectedUser] = React.useState(null);
    const [selectedJob, setSelectedJob] = React.useState(null);

    React.useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get('/admin/dashboard');
                setAdminData(response.data);
                setLoading(false);
            } catch (error) {
                console.error('Failed to fetch admin data:', error);
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    const deleteUser = async (userId) => {
        if (window.confirm('Are you sure you want to delete this user?')) {
            try {
                await axios.delete(`/admin/users/${userId}`);
                setAdminData(prev => ({
                    ...prev,
                    users: prev.users.filter(u => u.id !== userId)
                }));
            } catch (error) {
                alert('Failed to delete user');
            }
        }
    };

    const deleteJob = async (jobId) => {
        if (window.confirm('Are you sure you want to delete this job?')) {
            try {
                await axios.delete(`/admin/jobs/${jobId}`);
                setAdminData(prev => ({
                    ...prev,
                    jobs: prev.jobs.filter(j => j.id !== jobId)
                }));
            } catch (error) {
                alert('Failed to delete job');
            }
        }
    };

    const makeAdmin = async (userId) => {
        try {
            await axios.post(`/admin/make-admin/${userId}`);
            setAdminData(prev => ({
                ...prev,
                users: prev.users.map(u => 
                    u.id === userId ? { ...u, role: 'admin' } : u
                )
            }));
            alert('User promoted to admin');
        } catch (error) {
            alert('Failed to make admin');
        }
    };

    if (loading) {
        return (
            <div className="container mt-5 text-center">
                <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                </div>
                <p>Loading admin data...</p>
            </div>
        );
    }

    return (
        <div className="container">
            <div className="d-flex justify-content-between align-items-center mb-4">
                <h1>Admin Dashboard</h1>
                <button 
                    className="btn btn-outline-secondary" 
                    onClick={onBack}
                >
                    Back to Dashboard
                </button>
            </div>

            <div className="row">
                <div className="col-md-6">
                    <h2>Users ({adminData.users.length})</h2>
                    <div className="list-group mb-4" style={{ maxHeight: '500px', overflowY: 'auto' }}>
                        {adminData.users.map(user => (
                            <div 
                                key={user.id} 
                                className={`list-group-item ${selectedUser === user.id ? 'active' : ''}`}
                                onClick={() => setSelectedUser(user.id)}
                            >
                                <div className="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>{user.name}</strong>
                                        <div className="text-muted small">{user.email}</div>
                                        <span className={`badge ${user.role === 'admin' ? 'bg-danger' : 'bg-primary'}`}>
                                            {user.role}
                                        </span>
                                    </div>
                                    <div>
                                        {user.role !== 'admin' && (
                                            <button 
                                                className="btn btn-sm btn-success me-2"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    makeAdmin(user.id);
                                                }}
                                            >
                                                Make Admin
                                            </button>
                                        )}
                                        <button 
                                            className="btn btn-sm btn-danger"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                deleteUser(user.id);
                                            }}
                                        >
                                            Delete
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="col-md-6">
                    <h2>Jobs ({adminData.jobs.length})</h2>
                    <div className="list-group" style={{ maxHeight: '500px', overflowY: 'auto' }}>
                        {adminData.jobs.map(job => (
                            <div 
                                key={job.id} 
                                className={`list-group-item ${selectedJob === job.id ? 'active' : ''}`}
                                onClick={() => setSelectedJob(job.id)}
                            >
                                <div className="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>{job.title}</strong>
                                        <div className="text-muted small">${job.budget.toFixed(2)}</div>
                                        <span className={`badge ${
                                            job.status === 'open' ? 'bg-success' : 'bg-secondary'
                                        }`}>
                                            {job.status}
                                        </span>
                                    </div>
                                    <button 
                                        className="btn btn-sm btn-danger"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            deleteJob(job.id);
                                        }}
                                    >
                                        Delete
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

// Main App Component
function App() {
    const [currentPage, setCurrentPage] = React.useState('login');
    const [user, setUser] = React.useState(null);
    
    axios.defaults.baseURL = 'http://localhost:8080';
    
    React.useEffect(() => {
        const token = localStorage.getItem('token');
        const savedUser = localStorage.getItem('user');
        const privateKey = localStorage.getItem('privateKey');
        
        if (token && savedUser && privateKey) {
            axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
            setUser(JSON.parse(savedUser));
            setCurrentPage('dashboard');
        }
    }, []);
    
    const handleRegister = async (name, email, role, publicKey, privateKey) => {
        try {
            const response = await axios.post('/register', { 
                name, email, role, publicKey, privateKey
            });
            
            localStorage.setItem('privateKey', privateKey);
            localStorage.setItem(`privateKey_${email}`, privateKey);
            alert('Registration successful! Please login.');
            setCurrentPage('login');
            return true;
        } catch (error) {
            alert('Registration failed. Please try again.');
            return false;
        }
    };
    
    const handleLogin = async (email) => {
        try {
            // Step 1: Get nonce
            const initResponse = await axios.post('/login-init', { email });
            const nonce = initResponse.data.nonce;
            
            // Get private key from localStorage
            let privateKeyBase64 = localStorage.getItem(`privateKey_${email}`);
            if (!privateKeyBase64) {
                privateKeyBase64 = localStorage.getItem('privateKey');
            }
            
            if (!privateKeyBase64) {
                throw new Error('No private key found for this user');
            }
            
            const privateKeyBuffer = base64ToArrayBuffer(privateKeyBase64);
            
            const privateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                privateKeyBuffer,
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: "SHA-256"
                },
                true,
                ["sign"]
            );
            
            const signature = await signData(privateKey, nonce);
            
            // Step 3: Complete login
            const loginResponse = await axios.post('/login', {
                email,
                signature
            });
            
            // Save token and user data
            localStorage.setItem('token', loginResponse.data.token);
            localStorage.setItem('user', JSON.stringify(loginResponse.data.user));
            axios.defaults.headers.common['Authorization'] = `Bearer ${loginResponse.data.token}`;
            
            setUser(loginResponse.data.user);
            setCurrentPage('dashboard');
            return true;
        } catch (error) {
            alert('Login failed. Please check your credentials.');
            return false;
        }
    };
    
    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        delete axios.defaults.headers.common['Authorization'];
        setUser(null);
        setCurrentPage('login');
    };
    
    const handleCreateJob = async (jobData) => {
        try {
            await axios.post('/jobs', jobData);
            setCurrentPage('jobs');
            return true;
        } catch (error) {
            alert('Job creation failed: ' + (error.response?.data?.error || error.message));
            return false;
        }
    };
    
    const renderPage = () => {
        switch(currentPage) {
            case 'login':
                return <LoginPage 
                    onLogin={handleLogin} 
                    onNavigate={() => setCurrentPage('register')} 
                />;
            case 'register':
                return <RegisterPage 
                    onRegister={handleRegister} 
                    onNavigate={() => setCurrentPage('login')} 
                />;
            case 'dashboard':
                return <DashboardPage 
                    user={user} 
                    onLogout={handleLogout} 
                    onViewJobs={() => setCurrentPage('jobs')} 
                    onCreateJob={() => setCurrentPage('create-job')}
                    onViewAdmin={() => setCurrentPage('admin')}
                />;
            case 'jobs':
                return <JobsPage 
                    onBack={() => setCurrentPage('dashboard')}
                />;
            case 'create-job':
                return <CreateJobPage 
                    onCreate={handleCreateJob} 
                    onCancel={() => setCurrentPage('dashboard')} 
                />;
            case 'admin':
                return <AdminPanel 
                    onBack={() => setCurrentPage('dashboard')}
                />;
            default:
                return <LoginPage 
                    onLogin={handleLogin} 
                    onNavigate={() => setCurrentPage('register')} 
                />;
        }
    };
    
    return (
        <div className="container">
            {currentPage !== 'login' && currentPage !== 'register' && (
                <Navbar user={user} onLogout={handleLogout} />
            )}
            {renderPage()}
        </div>
    );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
