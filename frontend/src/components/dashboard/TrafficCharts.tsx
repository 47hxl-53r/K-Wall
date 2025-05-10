
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  PieChart, BarChart, Pie, Bar, Cell, XAxis, YAxis, 
  CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
  TooltipProps
} from "recharts";
import { 
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent
} from "@/components/ui/chart";
import { useState, useEffect } from "react";
import { ChartBarBig, ChartPie } from "lucide-react";

interface ChartData {
  labels: string[];
  datasets: Array<{
    label: string;
    data: number[];
    backgroundColor: string[];
  }>;
}

interface TrafficChartsProps {
  chartData?: ChartData;
}

export function TrafficCharts({ chartData }: TrafficChartsProps) {
  const [trafficDistributionData, setTrafficDistributionData] = useState<any[]>([]);
  const [blockReasonsData, setBlockReasonsData] = useState<any[]>([]);
  
  useEffect(() => {
    if (chartData) {
      // Format data for traffic distribution pie chart
      const trafficData = chartData.labels.slice(0, 2).map((label, index) => ({
        name: label,
        value: chartData.datasets[0].data[index] || 0,
        color: chartData.datasets[0].backgroundColor[index] || "#ccc"
      }));
      
      // Format data for block reasons bar chart
      const reasonsData = chartData.labels.slice(2).map((label, index) => ({
        name: label,
        value: chartData.datasets[1]?.data[index + 2] || 0,
        color: chartData.datasets[1]?.backgroundColor[index + 2] || "#ccc"
      })).filter(item => item.value > 0); // Only show reasons with values
      
      setTrafficDistributionData(trafficData);
      setBlockReasonsData(reasonsData);
    }
  }, [chartData]);

  if (!chartData) {
    return (
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-base font-medium">Traffic Distribution</CardTitle>
            <ChartPie className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent className="h-[300px] flex items-center justify-center">
            <p className="text-muted-foreground">No data available</p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-base font-medium">Block Reasons</CardTitle>
            <ChartBarBig className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent className="h-[300px] flex items-center justify-center">
            <p className="text-muted-foreground">No data available</p>
          </CardContent>
        </Card>
      </div>
    );
  }
  
  const customTooltip = ({ active, payload }: TooltipProps<number, string>) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-popover border border-border rounded-lg p-2 text-xs shadow-md">
          <p className="font-bold">{`${payload[0].name}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };
  
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-base font-medium">Traffic Distribution</CardTitle>
          <ChartPie className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            {trafficDistributionData.length > 0 && trafficDistributionData.some(item => item.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficDistributionData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    nameKey="name"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {trafficDistributionData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={customTooltip} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-muted-foreground">No traffic data available</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
      
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-base font-medium">Block Reasons</CardTitle>
          <ChartBarBig className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          {blockReasonsData.length > 0 ? (
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={blockReasonsData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip content={customTooltip} />
                  <Legend />
                  <Bar dataKey="value" name="Count">
                    {blockReasonsData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-[300px] flex items-center justify-center">
              <p className="text-muted-foreground">No blocked traffic</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
