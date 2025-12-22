import { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { createTvsApi } from '@/lib/api/tvs';

interface CertificateActionsProps {
  hash: string;
  subjectName: string;
}

export default function CertificateActions({ hash, subjectName }: CertificateActionsProps) {
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  const handleDelete = async () => {
    setIsDeleting(true);
    setError(null);

    try {
      const api = createTvsApi();
      await api.deleteCertificate(hash);
      window.location.href = '/certificates';
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete certificate');
      setIsDeleting(false);
    }
  };

  return (
    <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
      <DialogTrigger asChild>
        <Button variant="destructive" size="sm">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="mr-2 h-4 w-4"
          >
            <path d="M3 6h18" />
            <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" />
            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
          </svg>
          Delete
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete Certificate</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete the certificate for <strong>{subjectName}</strong>? This
            action cannot be undone and phones will no longer trust this certificate.
          </DialogDescription>
        </DialogHeader>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={isDeleting}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleDelete} disabled={isDeleting}>
            {isDeleting ? 'Deleting...' : 'Delete Certificate'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
