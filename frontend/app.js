// Main App Component
function App() {
  const [currentPage, setCurrentPage] = React.useState('login');
  const [user, setUser] = React.useState(null);
  const [jobs, setJobs] = React.useState([]);
  
  // Initialize Axios with base URL
  axios.defaults.baseURL = 'http://localhost:8080';
  
  // Check if user is logged in
  React.useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    
    if (token && savedUser) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setUser(JSON.parse(savedUser));
      setCurrentPage('dashboard');
      fetchJobs();
    }
  }, []);
  
  // Fetch jobs from backend
  const fetchJobs = async () => {
    try {
      const response = await axios.get('/jobs');
      setJobs(response.data);
    } catch (error) {
      console.error('Failed to fetch jobs', error);
    }
  };
  
  // Handle login
  const handleLogin = async (email, password) => {
    try {
      const response = await axios.post('/login', { email, password });
      
      // Save token and user data
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      
      setUser(response.data.user);
      setCurrentPage('dashboard');
      fetchJobs();
      return true;
    } catch (error) {
      alert('Login failed. Please check your credentials.');
      return false;
    }
  };
  
  // Handle registration
  const handleRegister = async (name, email, password, role) => {
    try {
      await axios.post('/register', { name, email, password, role });
      alert('Registration successful! Please login.');
      setCurrentPage('login');
      return true;
    } catch (error) {
      alert('Registration failed. Please try again.');
      return false;
    }
  };
  
  // Handle logout
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    setCurrentPage('login');
  };
  
  // Handle job creation
  const handleCreateJob = async (jobData) => {
    try {
      await axios.post('/jobs', jobData);
      fetchJobs();
      setCurrentPage('jobs');
      return true;
    } catch (error) {
      alert('Job creation failed');
      return false;
    }
  };
  
  // Render current page
  const renderPage = () => {
    switch(currentPage) {
      case 'login':
        return <LoginPage onLogin={handleLogin} onNavigate={() => setCurrentPage('register')} />;
      case 'register':
        return <RegisterPage onRegister={handleRegister} onNavigate={() => setCurrentPage('login')} />;
      case 'dashboard':
        return <DashboardPage user={user} onLogout={handleLogout} 
                  onViewJobs={() => setCurrentPage('jobs')} 
                  onCreateJob={() => setCurrentPage('create-job')} />;
      case 'jobs':
        return <JobsPage jobs={jobs} onBack={() => setCurrentPage('dashboard')} />;
      case 'create-job':
        return <CreateJobPage onCreate={handleCreateJob} onCancel={() => setCurrentPage('dashboard')} />;
      default:
        return <LoginPage onLogin={handleLogin} onNavigate={() => setCurrentPage('register')} />;
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

// Navbar Component
function Navbar({ user, onLogout }) {
  return (
    <nav className="navbar navbar-expand-lg navbar-light bg-light mb-4">
      <div className="container-fluid">
        <a className="navbar-brand" href="#" onClick={(e) => e.preventDefault()}>Eutelos</a>
        <div className="d-flex align-items-center">
          {user && (
            <>
              <span className="me-3">Hello, {user.name} ({user.role})</span>
              <button className="btn btn-outline-danger" onClick={onLogout}>
                Logout
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}

// Login Page Component
function LoginPage({ onLogin, onNavigate }) {
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onLogin(email, password);
    setLoading(false);
  };
  
  return (
    <div className="row justify-content-center mt-5">
      <div className="col-md-6">
        <div className="card">
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
              <div className="mb-3">
                <label className="form-label">Password</label>
                <input 
                  type="password" 
                  className="form-control"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
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

// Register Page Component
function RegisterPage({ onRegister, onNavigate }) {
  const [name, setName] = React.useState('');
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [role, setRole] = React.useState('client');
  const [loading, setLoading] = React.useState(false);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onRegister(name, email, password, role);
    setLoading(false);
  };
  
  return (
    <div className="row justify-content-center mt-5">
      <div className="col-md-6">
        <div className="card">
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
                <label className="form-label">Password</label>
                <input 
                  type="password" 
                  className="form-control"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
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
                  <option value="client">Client (I want to post jobs)</option>
                  <option value="freelancer">Freelancer (I want to find work)</option>
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

// Dashboard Page Component
function DashboardPage({ user, onLogout, onViewJobs, onCreateJob }) {
  return (
    <div>
      <h1 className="text-center mb-4">Welcome to Eutelos</h1>
      
      <div className="card">
        <div className="card-body">
          <h2>Your Dashboard</h2>
          <p><strong>Name:</strong> {user.name}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <p><strong>Role:</strong> {user.role}</p>
          
          <div className="mt-4">
            {user.role === 'client' ? (
              <>
                <p>As a client, you can post new jobs and manage existing ones</p>
                <button 
                  className="btn btn-primary me-2" 
                  onClick={onCreateJob}
                >
                  Create New Job
                </button>
              </>
            ) : (
              <p>As a freelancer, you can browse available jobs and submit proposals</p>
            )}
            <button 
              className="btn btn-secondary" 
              onClick={onViewJobs}
            >
              View All Jobs
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Jobs Page Component
function JobsPage({ jobs, onBack }) {
  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Available Jobs</h1>
        <button 
          className="btn btn-outline-secondary" 
          onClick={onBack}
        >
          Back to Dashboard
        </button>
      </div>
      
      {jobs.length === 0 ? (
        <div className="alert alert-info">No jobs available at the moment</div>
      ) : (
        <div className="row">
          {jobs.map(job => (
            <div key={job.id} className="col-md-6 mb-4">
              <div className="card h-100">
                <div className="card-body">
                  <h5 className="card-title">{job.title}</h5>
                  <p className="card-text">{job.description}</p>
                  <ul className="list-group list-group-flush">
                    <li className="list-group-item">
                      <strong>Budget:</strong> ${job.budget.toFixed(2)}
                    </li>
                    <li className="list-group-item">
                      <strong>Deadline:</strong> {job.deadline}
                    </li>
                    <li className="list-group-item">
                      <strong>Status:</strong> {job.status}
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

// Create Job Page Component
function CreateJobPage({ onCreate, onCancel }) {
  const [title, setTitle] = React.useState('');
  const [description, setDescription] = React.useState('');
  const [budget, setBudget] = React.useState('');
  const [deadline, setDeadline] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    const success = await onCreate({
      title,
      description,
      budget: parseFloat(budget),
      deadline
    });
    setLoading(false);
    
    if (success) {
      setTitle('');
      setDescription('');
      setBudget('');
      setDeadline('');
    }
  };
  
  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Create New Job</h1>
        <button 
          className="btn btn-outline-secondary" 
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
      
      <div className="card">
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

// Render the app
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
