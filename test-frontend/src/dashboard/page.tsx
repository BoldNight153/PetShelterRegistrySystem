export default function DashboardPage() {
  return (
    <div className="w-full flex-1 flex flex-col gap-4">
      <div className="grid auto-rows-min gap-4 md:grid-cols-3 w-full">
        <div className="bg-muted/50 aspect-video rounded-xl" />
        <div className="bg-muted/50 aspect-video rounded-xl" />
        <div className="bg-muted/50 aspect-video rounded-xl" />
      </div>
      <div className="bg-muted/50 mt-4 min-h-screen rounded-xl flex-1 w-full" />
    </div>
  )
}
