import { Link } from 'react-router-dom'
import { EmptyState } from '../components/Primitives'

export default function NotFound() {
  return <div className="page standard-page"><EmptyState title="Page not found." description="The page you're looking for doesn't exist or was moved." action={<Link className="button button-primary" to="/">Back to dashboard</Link>} /></div>
}
