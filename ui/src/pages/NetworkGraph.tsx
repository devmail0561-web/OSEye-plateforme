import { useState, useEffect, useRef } from 'react'
import * as d3 from 'd3'
import { Network } from 'lucide-react'
import { eventsApi } from '@/api/client'
import { EmptyState } from '@/components/ui'

interface Node {
  id: string
  type: 'host' | 'ip'
  label: string
  count: number
  x?: number
  y?: number
  fx?: number | null
  fy?: number | null
}

interface Link {
  source: string | Node
  target: string | Node
  count: number
}

const NODE_COLOR: Record<string, string> = {
  host: '#60a5fa',
  ip:   '#f97316',
}

export default function NetworkGraph() {
  const svgRef = useRef<SVGSVGElement>(null)
  const [loading, setLoading] = useState(false)
  const [nodeCount, setNodeCount] = useState(0)
  const [linkCount, setLinkCount] = useState(0)
  const [error, setError] = useState('')

  useEffect(() => {
    const ctrl = new AbortController()
    void build(ctrl.signal)
    return () => ctrl.abort()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function build(signal: AbortSignal) {
    setLoading(true)
    setError('')
    try {
      const data = await eventsApi.list({ category: 'network', limit: 250 })
      if (signal.aborted) return

      const nodesMap = new Map<string, Node>()
      const linksMap = new Map<string, Link>()

      const ensureNode = (id: string, type: 'host' | 'ip') => {
        if (!nodesMap.has(id)) nodesMap.set(id, { id, type, label: id, count: 0 })
        nodesMap.get(id)!.count++
      }

      for (const ev of data.items) {
        const src = ev.hostname
        const dst = ev.dst_ip
        if (!dst) continue
        ensureNode(src, 'host')
        ensureNode(dst, 'ip')
        const key = `${src}→${dst}`
        if (!linksMap.has(key)) linksMap.set(key, { source: src, target: dst, count: 0 })
        linksMap.get(key)!.count++
      }

      const nodes = Array.from(nodesMap.values())
      const links = Array.from(linksMap.values())
      setNodeCount(nodes.length)
      setLinkCount(links.length)

      if (!svgRef.current || nodes.length === 0) return
      renderGraph(nodes, links)
    } catch {
      if (!signal.aborted) setError('Erreur de chargement')
    } finally {
      if (!signal.aborted) setLoading(false)
    }
  }

  function renderGraph(nodes: Node[], links: Link[]) {
    const svg = d3.select(svgRef.current!)
    svg.selectAll('*').remove()

    const width  = svgRef.current!.clientWidth || 800
    const height = svgRef.current!.clientHeight || 520

    const g = svg.append('g')

    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.2, 4])
        .on('zoom', (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
          g.attr('transform', String(event.transform))
        })
    )

    const maxCount = Math.max(...links.map((l) => l.count), 1)

    const sim = d3
      .forceSimulation<Node>(nodes)
      .force('link', d3.forceLink<Node, Link>(links).id((d) => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(18))

    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#4b5563')
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', (d) => Math.max(1, (d.count / maxCount) * 4))

    const node = g.append('g')
      .selectAll<SVGCircleElement, Node>('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d) => Math.max(6, Math.min(16, 6 + d.count * 0.5)))
      .attr('fill', (d) => NODE_COLOR[d.type] ?? '#9ca3af')
      .attr('stroke', '#1f2937')
      .attr('stroke-width', 1.5)
      .call(
        d3.drag<SVGCircleElement, Node>()
          .on('start', (event: d3.D3DragEvent<SVGCircleElement, Node, Node>, d) => {
            if (!event.active) sim.alphaTarget(0.3).restart()
            d.fx = d.x; d.fy = d.y
          })
          .on('drag', (event: d3.D3DragEvent<SVGCircleElement, Node, Node>, d) => {
            d.fx = event.x; d.fy = event.y
          })
          .on('end', (event: d3.D3DragEvent<SVGCircleElement, Node, Node>, d) => {
            if (!event.active) sim.alphaTarget(0)
            d.fx = null; d.fy = null
          })
      )

    const label = g.append('g')
      .selectAll('text')
      .data(nodes)
      .join('text')
      .attr('font-size', 10)
      .attr('fill', '#9ca3af')
      .attr('text-anchor', 'middle')
      .attr('dy', -12)
      .text((d) => d.label.length > 18 ? d.label.slice(0, 16) + '…' : d.label)

    node.append('title').text((d) => `${d.label} (${d.count})`)

    sim.on('tick', () => {
      link
        .attr('x1', (d) => (d.source as Node).x ?? 0)
        .attr('y1', (d) => (d.source as Node).y ?? 0)
        .attr('x2', (d) => (d.target as Node).x ?? 0)
        .attr('y2', (d) => (d.target as Node).y ?? 0)
      node.attr('cx', (d) => d.x ?? 0).attr('cy', (d) => d.y ?? 0)
      label.attr('x', (d) => d.x ?? 0).attr('y', (d) => d.y ?? 0)
    })
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Graphe réseau</h1>
        <div className="flex items-center gap-4 text-xs text-gray-400 dark:text-gray-500">
          {loading && <span>Chargement…</span>}
          {!loading && !error && nodeCount > 0 && (
            <>
              <span>{nodeCount} nœuds</span>
              <span>{linkCount} connexions</span>
            </>
          )}
          {error && <span className="text-red-400">{error}</span>}
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-blue-400 inline-block" /> Hôte
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-orange-400 inline-block" /> IP externe
          </span>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-hidden" style={{ height: 540 }}>
        {!loading && nodeCount === 0 && !error ? (
          <EmptyState
            icon={Network}
            title="Aucun événement réseau"
            description="Les connexions réseau apparaîtront ici quand l'agent collecte des événements de type network"
          />
        ) : (
          <svg ref={svgRef} className="w-full h-full" />
        )}
      </div>

      <p className="text-xs text-gray-400 dark:text-gray-600">
        Basé sur les 250 derniers événements réseau · Glisser pour déplacer, molette pour zoomer
      </p>
    </div>
  )
}
